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
		Short: "Re-key the stored data with a new secret (not implemented)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// Deliberately not implemented rather than half-implemented.
			// Rotating means re-sealing every stored credential under keys
			// derived from the new secret, across replicas that must all switch
			// at once; a replica still on the old secret cannot open what a
			// replica on the new one has written. Client records, rules and
			// settings are not sealed and survive a rotation by hand.
			return errors.New(
				"secret rotation is not implemented: every stored backend and notifier credential is sealed " +
					"under keys derived from the current secret, and every replica must switch at once.\n\n" +
					"To rotate by hand: stop every replica, start them all with the new secret, then re-enter " +
					"each client's backend credentials with `pivot client backend <client-id>`, and remove and " +
					"re-add each notifier. Client ids, client secrets, rules and settings are unaffected")
		},
	}
}
