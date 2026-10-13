package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/protean/config"
	"github.com/adnoctem/netory/pkg/secret"
)

// newSecretCommand builds `protean secret`.
func newSecretCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Generate and rotate the service secret",
	}

	cmd.AddCommand(newSecretGenerateCommand(), newSecretRotateCommand())

	return cmd
}

// newSecretGenerateCommand builds `protean secret generate`.
//
// This works without a running server by necessity: it is how an operator
// produces the secret the server needs in order to start.
func newSecretGenerateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "generate",
		Short: "Generate a new service secret",
		Long: "Prints a new high-entropy secret for " + config.SecretEnv + ".\n\n" +
			"Works without a running server, since this is how the secret the server needs is produced.\n" +
			"Delivering it in a file through " + config.SecretFileEnv + " is preferable to an environment\n" +
			"variable: /proc/<pid>/environ is readable by the process owner, and environment variables\n" +
			"are inherited by child processes.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			value, err := secret.Generate()
			if err != nil {
				return err
			}

			// Printed bare, with no label, so `protean secret generate >
			// /etc/protean/secret` produces a usable file rather than one
			// containing a sentence.
			fmt.Fprintln(cmd.OutOrStdout(), value)

			return nil
		},
	}
}

// newSecretRotateCommand builds `protean secret rotate`.
func newSecretRotateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Re-key the stored data with a new secret (not implemented)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Deliberately not implemented rather than half-implemented.
			// Re-keying means re-encrypting the whole Badger database, and how
			// Badger's key registry behaves under re-keying is unverified. A
			// rotation that half-succeeds leaves a database nothing can open,
			// which is worse than one that has not been rotated.
			return errors.New(
				"secret rotation is not implemented: re-keying the database depends on how Badger's key " +
					"registry behaves under re-keying, which is unverified.\n\n" +
					"To rotate by hand, with the server stopped: export the data, start with the new secret, " +
					"and re-import")
		},
	}
}
