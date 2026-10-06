package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/server"
)

// newBackendCommand builds `pivot backend`.
//
// §3.1 drafted this as add|list|remove|test, which assumed backends were a
// collection. They are not: pivot fronts exactly one backend origin, and the
// per-customer part is a credential that belongs to a client record. So the
// verbs are show|set|test, and per-client credentials live under `client
// backend` where the thing they belong to is.
func newBackendCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backend",
		Short: "Inspect and set the backend pivot forwards to",
		Long: "pivot fronts one backend origin. The credentials are per customer and live on the\n" +
			"client record - see `pivot client backend` - because §6.2 requires each customer's\n" +
			"requests to reach the backend as that customer's own integration, with that\n" +
			"integration's permissions.\n\n" +
			"That is the second of the two layers: pivot's rules bound which paths a customer can\n" +
			"reach, and the backend's own permissions bound what those paths return. Data reachable\n" +
			"through an allowed entity's associations is controlled by the backend alone - no path\n" +
			"rule can see it.",
	}

	cmd.AddCommand(
		newBackendShowCommand(opts),
		newBackendSetCommand(opts),
		newBackendTestCommand(opts),
	)

	return cmd
}

func newBackendShowCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the configured backend",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var view server.ConfigurationResponse
			err = client.Get(cmd.Context(), server.APIPrefix+"/configuration", &view)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, map[string]string{
					"url":         view.Settings[app.SettingBackendURL],
					"timeout":     view.Bootstrap["backend.timeout"],
					"concurrency": view.Settings[app.SettingBackendConcurrency],
					"in_flight":   view.Serving["backend.in_flight"],
				})
			}

			t := newTable(out, "key", "value")
			t.row("url", view.Settings[app.SettingBackendURL])
			t.row("timeout", view.Bootstrap["backend.timeout"])
			t.row("concurrency (per replica)", view.Settings[app.SettingBackendConcurrency])
			t.row("in flight", view.Serving["backend.in_flight"])
			t.row("waiting", view.Serving["backend.waiting"])
			t.row("refused", view.Serving["backend.refused"])

			if err := t.flush(); err != nil {
				return err
			}

			fmt.Fprintln(out, "\nThe concurrency limit is per replica, so the effective ceiling on the")
			fmt.Fprintln(out, "backend is this value multiplied by the replica count.")

			return nil
		},
	}
}

func newBackendSetCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "set <url>",
		Short: "Set the origin requests are forwarded to",
		Long: "Sets the backend origin, as scheme://host[:port].\n\n" +
			"It may carry no path, query or fragment. pivot forwards the normalized request path\n" +
			"unchanged, so a base URL adding to it would make the forwarded path differ from the\n" +
			"one the rules matched - which is the one thing the whole rules layer depends on not\n" +
			"happening.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var entry server.SettingResponse

			err = client.Put(cmd.Context(),
				server.APIPrefix+"/config/"+app.SettingBackendURL,
				server.SettingRequest{Value: args[0]}, &entry)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "backend.url = %s\n", entry.Value)

			return nil
		},
	}
}

func newBackendTestCommand(opts *Options) *cobra.Command {
	var clientID string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Check that the backend accepts a customer's credentials",
		Long: "Makes one real request to the backend with a customer's credentials and reports what\n" +
			"came back.\n\n" +
			"It needs a client, because there are no instance-wide backend credentials: every\n" +
			"forward leg carries one customer's integration. A failure here is the thing that\n" +
			"would otherwise appear as a 502 to that customer and nothing in anyone's inbox.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if clientID == "" {
				return errors.New("--client is required: backend credentials are per customer")
			}

			return postMessage(cmd, opts,
				server.APIPrefix+"/clients/"+clientID+"/backend/test", nil, "POST")
		},
	}

	cmd.Flags().StringVar(&clientID, "client", "", "the client whose credentials to test")

	return cmd
}
