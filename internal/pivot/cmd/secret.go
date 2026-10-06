package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/pivot/config"
	"github.com/adnoctem/netory/pkg/secret"
)

// newSecretCommand builds `pivot secret`.
func newSecretCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Generate and rotate the service secret",
	}

	cmd.AddCommand(newSecretGenerateCommand(), newSecretRotateCommand())

	return cmd
}

// newSecretGenerateCommand builds `pivot secret generate`.
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

			// Printed bare, with no label, so `pivot secret generate >
			// /etc/pivot/secret` produces a usable file rather than one
			// containing a sentence.
			fmt.Fprintln(cmd.OutOrStdout(), value)

			return nil
		},
	}
}

// newSecretRotateCommand builds `pivot secret rotate`.
func newSecretRotateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate",
		Short: "Re-key the database with a new secret (not yet implemented)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// Deliberately not implemented rather than half-implemented.
			// Re-keying means re-encrypting the whole database, and Badger's
			// key-registry rotation behaviour is recorded as unverified in
			// protean's design document (section 10.3). A rotation that
			// half-succeeds leaves a database nothing can open, which is worse
			// than one that has not been rotated.
			//
			// pivot is better placed than protean to survive this: the
			// script contents live outside the database, so a rotation by hand
			// is republishing bundles rather than reconstructing credentials.
			return errors.New(
				"secret rotation is not implemented yet: re-keying the database depends on Badger's key " +
					"registry behaviour, which is recorded as unverified in docs/design/protean.md section 10.3.\n\n" +
					"To rotate by hand, with the server stopped: start with the new secret against an empty " +
					"database and republish the bundles you need. The releases themselves are files on disk, " +
					"so nothing is lost by doing it that way")
		},
	}
}
