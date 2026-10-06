package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/protean/server"
)

// newConfigViewCommand builds `protean config view`.
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
			"stored in the database, and what the database holds.\n\n" +
			"Credentials never appear: the service secret is not part of the configuration struct,\n" +
			"and provider and notifier credentials are not configuration - see `provider list` and\n" +
			"`notifier list`, which redact them.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var view server.ConfigurationView
			if err := client.Get(cmd.Context(), server.APIPrefix+"/configuration", &view); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, view)
			}

			fmt.Fprintf(out, "protean %s\n\n", view.Version)

			// The two halves are labelled with what changing them costs,
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

			fmt.Fprintln(out, "\nRuntime settings (stored in the database; changing it takes effect at once)")

			settings := newTable(out, "  setting", "value", "description")
			for _, entry := range view.Settings {
				settings.row("  "+entry.Name, entry.Value, entry.Help)
			}

			if err := settings.flush(); err != nil {
				return err
			}

			fmt.Fprintln(out, "\nStored")

			counts := newTable(out, "  collection", "count")
			counts.row("  hosts", strconv.Itoa(view.Counts.Hosts))
			counts.row("  tokens", strconv.Itoa(view.Counts.Tokens))
			counts.row("  providers", strconv.Itoa(view.Counts.Providers))
			counts.row("  notifiers", strconv.Itoa(view.Counts.Notifiers))
			counts.row("  outbox pending", strconv.Itoa(view.Counts.Pending))
			counts.row("  outbox dead", strconv.Itoa(view.Counts.Dead))

			return counts.flush()
		},
	}
}
