package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/signpost/server"
)

// newConfigCommand builds `signpost config`.
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
			"The bootstrap configuration - listen address, socket, database and content paths, TLS\n" +
			"files - belongs to `signpost server start` instead, since those values are needed\n" +
			"before the database can be opened.",
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

			var entries []server.SettingResponse
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

			var entry server.SettingResponse
			if err := client.Get(cmd.Context(), server.APIPrefix+"/config/"+args[0], &entry); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, entry)
			}

			// The bare value, so `signpost config get serve.alias` is usable
			// in a script without post-processing.
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
			"Run `signpost config list` to see the settings and what they accept.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var entry server.SettingResponse
			err = client.Put(cmd.Context(), server.APIPrefix+"/config/"+args[0],
				server.SettingRequest{Value: args[1]}, &entry)
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

// newConfigViewCommand builds `signpost config view`.
//
// One command that answers "what is this server actually doing", rather than
// making an operator run `config get` once per key - and then remember that
// the listen address and the TLS mode are not settings at all, so `config get`
// would never have shown them.
func newConfigViewCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "view",
		Short: "Show the whole active configuration",
		Long: "Shows the bootstrap configuration the server was started with, the runtime settings\n" +
			"stored in the database, and what the public listener is currently serving.\n\n" +
			"Credentials never appear: the service secret is not part of the configuration struct,\n" +
			"and notifier credentials are not configuration - see `notifier list`, which redacts\n" +
			"them. The signing key is shown in full, because a public key is public and checking\n" +
			"which one is trusted is the point of having it here.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var view server.ConfigurationResponse
			if err := client.Get(cmd.Context(), server.APIPrefix+"/configuration", &view); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, view)
			}

			// The sections are labelled with what changing them costs,
			// because that is the distinction an operator actually needs: one
			// requires a restart and the other does not.
			fmt.Fprintln(out, "Bootstrap configuration (set at startup; changing it needs a restart)")

			bootstrap := newTable(out, "  key", "value")
			for _, key := range sortedKeys(view.Bootstrap) {
				bootstrap.row("  "+key, view.Bootstrap[key])
			}

			if err := bootstrap.flush(); err != nil {
				return err
			}

			fmt.Fprintln(out, "\nRuntime settings (stored in the database; changing one takes effect at once)")

			settings := newTable(out, "  setting", "value")
			for _, key := range sortedKeys(view.Settings) {
				settings.row("  "+key, view.Settings[key])
			}

			if err := settings.flush(); err != nil {
				return err
			}

			fmt.Fprintln(out, "\nServing")

			serving := newTable(out, "  key", "value")
			for _, key := range sortedKeys(view.Serving) {
				serving.row("  "+key, dash(view.Serving[key]))
			}

			return serving.flush()
		},
	}
}
