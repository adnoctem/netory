package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/protean/server"
)

// newConfigCommand builds `protean config`.
//
// These are the runtime settings, stored in the database. The bootstrap
// values - the listen address, the paths, the TLS files - are flags and
// environment variables on `server start`, because they are needed before the
// database can be opened.
func newConfigCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Get and set the runtime settings",
		Long: "Manages the settings stored in the database, which take effect without a restart.\n\n" +
			"The bootstrap configuration - listen address, socket and database paths, TLS files -\n" +
			"belongs to `protean server start` instead, since those values are needed before the\n" +
			"database can be opened.",
	}

	cmd.AddCommand(
		newConfigViewCommand(opts),
		newConfigListCommand(opts),
		newConfigGetCommand(opts),
		newConfigSetCommand(opts),
	)

	return cmd
}

func newConfigListCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List every setting with its current value",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var entries []server.ConfigEntry
			if err := client.Get(cmd.Context(), server.APIPrefix+"/config", &entries); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, entries)
			}

			t := newTable(out, "setting", "value", "description")
			for _, entry := range entries {
				t.row(entry.Name, entry.Value, entry.Help)
			}

			return t.flush()
		},
	}
}

func newConfigGetCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <setting>",
		Short: "Print one setting's value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var entry server.ConfigEntry
			if err := client.Get(cmd.Context(), server.APIPrefix+"/config/"+args[0], &entry); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, entry)
			}

			// The bare value, so `protean config get ratelimit.per_host` is
			// usable in a script without post-processing.
			fmt.Fprintln(out, entry.Value)

			return nil
		},
	}
}

func newConfigSetCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "set <setting> <value>",
		Short: "Change one setting",
		Long: "Changes a setting and applies it immediately.\n\n" +
			"Run `protean config list` to see the settings and what they accept.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var entry server.ConfigEntry
			err = client.Put(cmd.Context(), server.APIPrefix+"/config/"+args[0],
				server.ConfigSetRequest{Value: args[1]}, &entry)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, entry)
			}

			fmt.Fprintf(out, "%s = %s\n", entry.Name, entry.Value)

			return nil
		},
	}
}
