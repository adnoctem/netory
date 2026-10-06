package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/pivot/server"
)

// newTokenCommand builds `pivot token`.
func newTokenCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "token",
		Short:   "Manage issued access tokens",
		Aliases: []string{"tokens"},
		Long: "Access tokens are what customers present on each request in oauth2 and bearer mode.\n\n" +
			"They are opaque rather than self-contained, which is what makes them revocable: a\n" +
			"token is already a lookup, so revoking one is deleting a key. Only the SHA-256 hash is\n" +
			"stored, so `token list` shows hashes and never tokens - and `token revoke` takes a\n" +
			"hash for the same reason.\n\n" +
			"Customers normally obtain their own through the token endpoint. `token create` is for\n" +
			"a longer-lived one an operator issues deliberately, such as for a CI pipeline.",
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
	var (
		label    string
		lifetime time.Duration
	)

	cmd := &cobra.Command{
		Use:   "create <client-id>",
		Short: "Issue a token for a customer and print it once",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			request := server.TokenRequest{ClientID: args[0], Label: label}
			if cmd.Flags().Changed("lifetime") {
				request.Lifetime = lifetime.String()
			}

			var created server.TokenResponse
			if err := client.Post(cmd.Context(), server.APIPrefix+"/tokens", request, &created); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, created)
			}

			fmt.Fprintf(out, "  token:      %s\n", created.Token)
			fmt.Fprintf(out, "  hash:       %s\n", created.Hash)
			fmt.Fprintf(out, "  client:     %s\n", created.ClientID)
			fmt.Fprintf(out, "  expires at: %s\n\n", created.ExpiresAt.Format(time.RFC3339))
			fmt.Fprintln(out, "The token is shown once. Revoke it with:")
			fmt.Fprintf(out, "  pivot token revoke %s\n", created.Hash)

			return nil
		},
	}

	cmd.Flags().StringVar(&label, "label", "",
		"a note distinguishing this token, such as the system that holds it")
	cmd.Flags().DurationVar(&lifetime, "lifetime", 0,
		"how long the token is valid; defaults to the configured token lifetime")

	return cmd
}

func newTokenListCommand(opts *Options) *cobra.Command {
	var forClient string

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List the live tokens",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			path := server.APIPrefix + "/tokens"
			if forClient != "" {
				path += "?client=" + urlQueryEscape(forClient)
			}

			var tokens []server.TokenResponse
			if err := client.Get(cmd.Context(), path, &tokens); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, tokens)
			}

			if len(tokens) == 0 {
				fmt.Fprintln(out, "no live tokens")

				return nil
			}

			t := newTable(out, "hash", "client", "label", "expires in", "issued by")
			for _, token := range tokens {
				t.row(
					token.Hash[:16]+"…",
					token.ClientID,
					dash(token.Label),
					shortDuration(time.Until(token.ExpiresAt)),
					token.IssuedBy,
				)
			}

			if err := t.flush(); err != nil {
				return err
			}

			fmt.Fprintln(out, "\nhashes are truncated for display; `--json` prints them in full")

			return nil
		},
	}

	cmd.Flags().StringVar(&forClient, "client", "", "only this client's tokens")

	return cmd
}

func newTokenRevokeCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <hash>",
		Short: "Revoke one token by its hash",
		Long: "Revokes a token immediately.\n\n" +
			"The argument is the hash from `token list`, not the token: pivot never holds a usable\n" +
			"token, so a hash is the only identifier it can offer.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			if err := client.Delete(cmd.Context(), server.APIPrefix+"/tokens/"+args[0]); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "revoked %s\n", args[0])

			return nil
		},
	}
}

func newTokenRotateCommand(opts *Options) *cobra.Command {
	var label string

	cmd := &cobra.Command{
		Use:   "rotate <client-id> <hash>",
		Short: "Issue a replacement token and revoke the old one",
		Long: "Issues a new token for a client, prints it, and then revokes the old one.\n\n" +
			"In that order on purpose: the new token exists before the old one stops working, so a\n" +
			"rotation has no window in which the holder has neither.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var created server.TokenResponse

			err = client.Post(cmd.Context(), server.APIPrefix+"/tokens",
				server.TokenRequest{ClientID: args[0], Label: label}, &created)
			if err != nil {
				return err
			}

			// The old one goes only after the new one is in hand.
			if err := client.Delete(cmd.Context(), server.APIPrefix+"/tokens/"+args[1]); err != nil {
				return fmt.Errorf(
					"issued the new token %s but could not revoke the old one: %w", created.Hash, err)
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, created)
			}

			fmt.Fprintf(out, "  token:   %s\n", created.Token)
			fmt.Fprintf(out, "  hash:    %s\n", created.Hash)
			fmt.Fprintf(out, "  revoked: %s\n", args[1])

			return nil
		},
	}

	cmd.Flags().StringVar(&label, "label", "", "a note for the replacement token")

	return cmd
}
