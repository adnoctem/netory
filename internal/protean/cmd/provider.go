package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/protean/provider"
	"github.com/adnoctem/netory/internal/protean/server"
)

// newProviderCommand builds `protean provider`.
func newProviderCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "provider",
		Short:   "Manage DNS provider instances",
		Aliases: []string{"providers"},
	}

	cmd.AddCommand(
		newProviderAddCommand(opts),
		newProviderListCommand(opts),
		newProviderRemoveCommand(opts),
		newProviderTestCommand(opts),
	)

	return cmd
}

func newProviderAddCommand(opts *Options) *cobra.Command {
	var (
		kind     string
		zone     string
		settings []string
	)

	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a provider instance",
		Long: "Adds a provider instance: a kind, a zone, and the credentials for it.\n\n" +
			"Providers are compiled into the binary, so the available kinds are fixed at build\n" +
			"time: " + strings.Join(provider.Kinds(), ", ") + ".\n\n" +
			"Credentials should be least-privilege - a zone-scoped Cloudflare token, an IAM policy\n" +
			"restricted to the hosted zone. protean cannot verify that, because the provider APIs\n" +
			"offer no way to ask what a credential is scoped to; it is the operator's\n" +
			"responsibility and worth doing.\n\n" +
			"Settings are given as --set key=value, repeatable. For example:\n" +
			"  protean provider add cf-main --kind cloudflare --zone example.org \\\n" +
			"    --set api_token=$CF_TOKEN",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			parsed, err := parseSettings(settings)
			if err != nil {
				return err
			}

			cfg := provider.Config{Name: args[0], Kind: kind, Zone: zone, Settings: parsed}

			var created server.ProviderResponse
			if err := client.Post(cmd.Context(), server.APIPrefix+"/providers", cfg, &created); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, created)
			}

			fmt.Fprintf(out, "Added provider %q (%s) for zone %s.\n", created.Name, created.Kind, created.Zone)
			fmt.Fprintf(out, "\nVerify the credentials with:\n  protean provider test %s\n", created.Name)

			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "provider kind: "+strings.Join(provider.Kinds(), ", "))
	cmd.Flags().StringVar(&zone, "zone", "", "the DNS zone this instance manages")
	cmd.Flags().StringArrayVar(&settings, "set", nil, "credential or option as key=value, repeatable")

	for _, flag := range []string{"kind", "zone"} {
		if err := cmd.MarkFlagRequired(flag); err != nil {
			panic(err)
		}
	}

	return cmd
}

func newProviderListCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List the configured providers",
		Long:    "Lists the provider instances. Credentials are always redacted.",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var providers []server.ProviderResponse
			if err := client.Get(cmd.Context(), server.APIPrefix+"/providers", &providers); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, providers)
			}

			if len(providers) == 0 {
				fmt.Fprintf(out, "No providers configured. Add one with `protean provider add`.\n")
				fmt.Fprintf(out, "This binary supports: %s\n", strings.Join(provider.Kinds(), ", "))

				return nil
			}

			t := newTable(out, "name", "kind", "zone", "settings")
			for _, p := range providers {
				t.row(p.Name, p.Kind, p.Zone, renderSettings(p.Settings))
			}

			return t.flush()
		},
	}
}

func newProviderRemoveCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a provider instance",
		Long: "Removes a provider instance.\n\n" +
			"Refused while any host still references it: a host whose provider is gone would accept\n" +
			"updates and then fail to write them, which presents as a DNS outage rather than as the\n" +
			"configuration error it is.",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			if err := client.Delete(cmd.Context(), server.APIPrefix+"/providers/"+args[0]); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Removed provider %q.\n", args[0])

			return nil
		},
	}
}

func newProviderTestCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "test <name>",
		Short: "Check a provider's credentials",
		Long: "Reads the zone to confirm the credentials work and the zone is reachable.\n\n" +
			"Read-only: nothing is written, so this is safe to run against a live zone.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var result server.TestResponse
			err = client.Post(cmd.Context(), server.APIPrefix+"/providers/"+args[0]+"/test", nil, &result)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, result)
			}

			if !result.OK {
				// A non-zero exit, so this is usable in a health check or a
				// deployment script rather than only by eye.
				fmt.Fprintf(cmd.ErrOrStderr(), "provider %q: %s\n", args[0], result.Message)

				return errors.New("provider test failed")
			}

			fmt.Fprintf(out, "provider %q: %s\n", args[0], result.Message)

			return nil
		},
	}
}

// parseSettings turns repeated --set key=value flags into a map.
func parseSettings(entries []string) (map[string]string, error) {
	settings := make(map[string]string, len(entries))

	for _, entry := range entries {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			return nil, fmt.Errorf("--set %q is not key=value", entry)
		}

		key = strings.TrimSpace(key)
		if key == "" {
			return nil, fmt.Errorf("--set %q has an empty key", entry)
		}

		// The value is not trimmed: a credential could legitimately end in
		// whitespace, and silently altering one would be a maddening bug to
		// track down.
		if _, duplicate := settings[key]; duplicate {
			return nil, fmt.Errorf("--set %s given more than once", key)
		}

		settings[key] = value
	}

	return settings, nil
}
