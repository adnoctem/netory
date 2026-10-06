package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/internal/protean/server"
)

// newTokenCommand builds `protean token`.
func newTokenCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "token",
		Short:   "Manage per-host update tokens",
		Aliases: []string{"tokens"},
	}

	cmd.AddCommand(
		newTokenCreateCommand(opts),
		newTokenListCommand(opts),
		newTokenRevokeCommand(opts),
		newTokenRotateCommand(opts),
	)

	return cmd
}

func newTokenCreateCommand(opts *Options) *cobra.Command {
	var label string

	cmd := &cobra.Command{
		Use:   "create <hostname>",
		Short: "Issue a token for a host",
		Long: "Issues a token scoped to one host.\n\n" +
			"The token is shown once and never again: only its hash is stored, so it cannot be\n" +
			"recovered. If it is lost, issue another - a host may hold several, which is what\n" +
			"makes rotation possible without downtime.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var created server.TokenResponse
			err = client.Post(cmd.Context(), server.APIPrefix+"/tokens",
				server.TokenRequest{Host: args[0], Label: label}, &created)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, created)
			}

			fmt.Fprintf(out, "Token issued for %s.\n\n", created.Host)
			fmt.Fprintf(out, "  id:    %s\n", created.ID)
			fmt.Fprintf(out, "  token: %s\n\n", created.Value)
			fmt.Fprintln(out, "This is the only time the token is shown. Store it now.")
			fmt.Fprintf(out,
				"\nConfigure a client with:\n  https://%s:<token>@<protean-host>/nic/update?hostname=%s\n",
				created.Host, created.Host)

			return nil
		},
	}

	cmd.Flags().StringVar(&label, "label", "", "note recording which client holds this token")

	return cmd
}

func newTokenListCommand(opts *Options) *cobra.Command {
	var host string

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List the issued tokens",
		Long:    "Lists tokens by ID. The token values are not stored and cannot be listed.",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			path := server.APIPrefix + "/tokens"
			if host != "" {
				path += "?host=" + host
			}

			var tokens []app.Token
			if err := client.Get(cmd.Context(), path, &tokens); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, tokens)
			}

			if len(tokens) == 0 {
				fmt.Fprintln(out, "No tokens issued. Issue one with `protean token create <hostname>`.")

				return nil
			}

			t := newTable(out, "id", "host", "label", "created")
			for _, token := range tokens {
				t.row(
					token.ID,
					token.Host,
					dash(token.Label),
					shortDuration(time.Since(token.CreatedAt))+" ago",
				)
			}

			return t.flush()
		},
	}

	cmd.Flags().StringVar(&host, "host", "", "show only this host's tokens")

	return cmd
}

func newTokenRevokeCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <token-id>",
		Short: "Revoke a token",
		Long: "Revokes a token by its ID, which `protean token list` shows.\n\n" +
			"Takes effect immediately: authentication is a store lookup on every request, with\n" +
			"nothing cached.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			if err := client.Delete(cmd.Context(), server.APIPrefix+"/tokens/"+args[0]); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Revoked token %s. It stops working immediately.\n", args[0])

			return nil
		},
	}
}

func newTokenRotateCommand(opts *Options) *cobra.Command {
	var label string

	cmd := &cobra.Command{
		Use:   "rotate <token-id>",
		Short: "Issue a replacement token and revoke the old one",
		Long: "Issues a new token for the same host and revokes the old one.\n\n" +
			"The new token is created first, so a failure in between leaves the host with two\n" +
			"working tokens rather than none - a locked-out client stops updating and nobody\n" +
			"notices until the address changes.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var created server.TokenResponse
			err = client.Post(cmd.Context(), server.APIPrefix+"/tokens/"+args[0]+"/rotate",
				server.TokenRequest{Label: label}, &created)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, created)
			}

			fmt.Fprintf(out, "Rotated the token for %s.\n\n", created.Host)
			fmt.Fprintf(out, "  old id: %s (revoked)\n", args[0])
			fmt.Fprintf(out, "  new id: %s\n", created.ID)
			fmt.Fprintf(out, "  token:  %s\n\n", created.Value)
			fmt.Fprintln(out, "This is the only time the new token is shown. Update the client now.")

			return nil
		},
	}

	cmd.Flags().StringVar(&label, "label", "", "replace the label; empty keeps the old one")

	return cmd
}
