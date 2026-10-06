package cmd

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/protean/server"
	"github.com/adnoctem/netory/pkg/backup"
)

// newBackupCommand builds `protean backup`.
//
// create, list and verify go through the admin socket, because the server holds
// the database and - on EC2 or EKS - the role that can reach S3. restore does
// not: it needs the database closed, so there is by definition no server to ask.
func newBackupCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "backup",
		Short:   "Create, list, verify and restore database backups",
		Aliases: []string{"backups"},
		Long: "Backups are sealed with AES-256-GCM under a key derived from the service secret.\n\n" +
			"That is not belt-and-braces: Badger's own backup reads key-value pairs through the\n" +
			"normal transaction path, so a backup of an encrypted database is a plaintext stream of\n" +
			"every host, token hash, provider credential and notifier password in it. Writing one\n" +
			"unsealed would undo the database encryption silently.\n\n" +
			"The consequence is worth stating plainly: a backup is only restorable with the secret\n" +
			"that made it. Back the secret up somewhere other than next to the backups.",
	}

	cmd.AddCommand(
		newBackupCreateCommand(opts),
		newBackupListCommand(opts),
		newBackupVerifyCommand(opts),
		newBackupRestoreCommand(),
	)

	return cmd
}

// destinationFlag is the shared `--at` flag description, since all four
// subcommands take the same thing.
const destinationFlagHelp = "where backups live: a directory path, or s3://bucket/prefix"

func newBackupCreateCommand(opts *Options) *cobra.Command {
	var destination string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Take a backup of the running database",
		Long: "Takes a consistent snapshot of the live database, seals it, and stores it.\n\n" +
			"The server is not stopped and writers are not blocked: Badger streams at a transaction\n" +
			"timestamp, so a scheduled backup of a running service is safe.\n\n" +
			"S3 destinations use the AWS credential chain - an instance or task role, the shared\n" +
			"config, or the environment - and the work is done by the server, which is the process\n" +
			"that already has an identity.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var result server.BackupResult
			err = client.Post(cmd.Context(), server.APIPrefix+"/backups",
				server.BackupRequest{Destination: destination}, &result)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, result)
			}

			fmt.Fprintf(out, "Backup written to %s\n\n", result.Destination)
			fmt.Fprintf(out, "  name:    %s\n", result.Name)
			fmt.Fprintf(out, "  size:    %s sealed (%s before sealing)\n",
				humanBytes(result.StoredSize), humanBytes(result.PlainSize))
			fmt.Fprintf(out, "  sha256:  %s\n", result.SHA256)
			fmt.Fprintf(out, "  version: %d\n", result.Version)
			fmt.Fprintf(out, "\nVerify it with:\n  protean backup verify %s --at %s\n",
				result.Name, destination)

			return nil
		},
	}

	cmd.Flags().StringVar(&destination, "at", "", destinationFlagHelp)

	if err := cmd.MarkFlagRequired("at"); err != nil {
		panic(err)
	}

	return cmd
}

func newBackupListCommand(opts *Options) *cobra.Command {
	var destination string

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List the stored backups, newest first",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var response server.BackupListResponse
			err = client.Get(cmd.Context(),
				server.APIPrefix+"/backups?destination="+urlQueryEscape(destination), &response)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, response)
			}

			if len(response.Entries) == 0 {
				fmt.Fprintf(out, "No backups at %s.\n", response.Destination)
				fmt.Fprintln(out, "Take one with `protean backup create --at <destination>`.")

				return nil
			}

			fmt.Fprintf(out, "%s\n\n", response.Destination)

			t := newTable(out, "name", "size", "age")
			for _, entry := range response.Entries {
				t.row(entry.Name, humanBytes(entry.Size), backupAge(entry))
			}

			return t.flush()
		},
	}

	cmd.Flags().StringVar(&destination, "at", "", destinationFlagHelp)

	if err := cmd.MarkFlagRequired("at"); err != nil {
		panic(err)
	}

	return cmd
}

func newBackupVerifyCommand(opts *Options) *cobra.Command {
	var destination string

	cmd := &cobra.Command{
		Use:   "verify <name>",
		Short: "Check that a stored backup decrypts and is intact",
		Long: "Downloads a backup and confirms it decrypts under this server's secret.\n\n" +
			"Nothing is restored and nothing is changed. Worth running on a schedule: a backup\n" +
			"nobody has ever opened is a backup nobody knows works, and an incident is the wrong\n" +
			"moment to find out.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var result server.BackupVerifyResponse
			err = client.Post(cmd.Context(), server.APIPrefix+"/backups/verify",
				server.BackupRequest{Destination: destination, Name: args[0]}, &result)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, result)
			}

			if !result.OK {
				// A non-zero exit, so this is usable in a monitoring check
				// rather than only by eye.
				fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", result.Name, result.Message)

				return errors.New("backup verification failed")
			}

			fmt.Fprintf(out, "%s: %s (%s of data)\n",
				result.Name, result.Message, humanBytes(result.PlainSize))

			return nil
		},
	}

	cmd.Flags().StringVar(&destination, "at", "", destinationFlagHelp)

	if err := cmd.MarkFlagRequired("at"); err != nil {
		panic(err)
	}

	return cmd
}

// humanBytes renders a size for an operator rather than for a machine.
func humanBytes(n int64) string {
	const unit = 1024

	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}

	value := float64(n)
	units := []string{"KiB", "MiB", "GiB", "TiB"}

	for _, suffix := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, suffix)
		}
	}

	return fmt.Sprintf("%.1f PiB", value/unit)
}

// backupAge renders when a backup was taken, as an age - which answers "is the
// backup schedule still running?" at a glance.
func backupAge(entry backup.Entry) string {
	if entry.ModTime.IsZero() {
		return "unknown"
	}

	return shortDuration(time.Since(entry.ModTime)) + " ago"
}
