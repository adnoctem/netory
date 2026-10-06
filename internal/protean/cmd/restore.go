package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/internal/protean/config"
	"github.com/adnoctem/netory/pkg/backup"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
	"github.com/adnoctem/netory/pkg/log"
	"github.com/adnoctem/netory/pkg/secret"
)

// newBackupRestoreCommand builds `protean backup restore`.
//
// Offline by necessity, not by preference. Badger holds an exclusive lock on
// its directory, so the server must be stopped for anything else to open it -
// and it should be, because Badger's load *merges* rather than replaces: keys
// in the backup overwrite their counterparts and keys absent from it survive.
// Restoring onto a live database would produce a mixture that is neither the
// backup nor what was there before.
//
// So this command opens the database directly, which also means it needs the
// secret and - for an S3 source - credentials of its own.
func newBackupRestoreCommand() *cobra.Command {
	var (
		source   string
		database string
		force    bool
	)

	cmd := &cobra.Command{
		Use:   "restore <name>",
		Short: "Restore a backup into a stopped database",
		Long: "Restores a backup. The server must be stopped: Badger holds an exclusive lock on its\n" +
			"directory, and this command opens it directly.\n\n" +
			"Refuses a database that already holds data, because Badger's load merges rather than\n" +
			"replaces - keys in the backup overwrite their counterparts and keys absent from it\n" +
			"survive, so the result would be neither the backup nor what was there before. Use\n" +
			"--force only when that is genuinely what you want.\n\n" +
			"The backup is decrypted with the service secret, read from " + config.SecretEnv + " or\n" +
			config.SecretFileEnv + ". It must be the secret the backup was made with.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRestore(cmd, args[0], source, database, force)
		},
	}

	cmd.Flags().StringVar(&source, "from", "", destinationFlagHelp)
	cmd.Flags().StringVar(&database, "database", config.DefaultDatabase, "the database directory to restore into")
	cmd.Flags().BoolVar(&force, "force", false,
		"restore into a database that already holds data, merging the backup over it")

	if err := cmd.MarkFlagRequired("from"); err != nil {
		panic(err)
	}

	return cmd
}

// runRestore performs an offline restore.
func runRestore(cmd *cobra.Command, name, source, database string, force bool) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()

	raw, err := config.ReadSecret()
	if err != nil {
		return err
	}

	sec, err := secret.Parse(raw)
	if err != nil {
		return err
	}

	dest, err := backup.Open(ctx, source)
	if err != nil {
		return err
	}

	sealed, err := dest.Get(ctx, name)
	if err != nil {
		if errors.Is(err, backup.ErrNotFound) {
			return fmt.Errorf("%w\n\nRun `protean backup list --at %s` to see the stored names", err, source)
		}

		return err
	}

	key, err := app.BackupKey(sec)
	if err != nil {
		return err
	}

	// Decrypted before the database is touched, so a wrong secret or a corrupt
	// backup fails without having modified anything.
	plain, err := backup.Unseal(key, sealed)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "Backup %s opened: %s of data.\n", name, humanBytes(int64(len(plain))))

	store, err := openDatabaseForRestore(database, sec)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	empty, err := store.IsEmpty()
	if err != nil {
		return err
	}

	if !empty && !force {
		return fmt.Errorf(
			"the database at %s already holds data, and restoring would merge the backup over it "+
				"rather than replace it.\n\n"+
				"Move or remove the directory and restore into a fresh one, which is almost always "+
				"what a restore means - or pass --force if merging is genuinely what you want",
			database)
	}

	if !empty {
		fmt.Fprintln(out, "Merging into a database that already holds data, because --force was given.")
	}

	if err := store.Restore(bytes.NewReader(plain)); err != nil {
		return err
	}

	fmt.Fprintf(out, "Restored into %s.\n", database)
	fmt.Fprintln(out, "\nStart the server, then check `protean host list` and `protean provider list`.")

	return nil
}

// openDatabaseForRestore opens the target database directly.
//
// A running server would hold Badger's directory lock, so a failure here is
// most often that - and the error says so, because "resource temporarily
// unavailable" from a lock file explains nothing on its own.
func openDatabaseForRestore(database string, sec *secret.Secret) (*badgerkv.Store, error) {
	encryptionKey, err := sec.DeriveEncryptionKey(app.InfoKVEncryption)
	if err != nil {
		return nil, err
	}

	// A quiet logger: Badger's startup chatter is noise in a one-off command,
	// and anything that matters is returned as an error.
	logger := log.New(log.WithOutput(os.Stderr), log.WithLevel(slogLevelWarn))

	store, err := badgerkv.New(badgerkv.Options{
		Path:          database,
		EncryptionKey: encryptionKey,
		Logger:        logger,

		// No background value-log collection for a one-off command.
		GCInterval: -1,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"could not open the database at %s: %w\n\n"+
				"If the server is running, stop it first - Badger holds an exclusive lock on its "+
				"directory, so only one process may open it",
			database, err)
	}

	return store, nil
}
