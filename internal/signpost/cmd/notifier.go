package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/signpost/app"
	"github.com/adnoctem/netory/internal/signpost/server"
	"github.com/adnoctem/netory/pkg/notify"
)

// newNotifierCommand builds `signpost notifier`.
func newNotifierCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "notifier",
		Short:   "Manage notification transports",
		Aliases: []string{"notifiers"},
	}

	cmd.AddCommand(
		newNotifierAddCommand(opts),
		newNotifierListCommand(opts),
		newNotifierRemoveCommand(opts),
		newNotifierTestCommand(opts),
	)

	return cmd
}

func newNotifierAddCommand(opts *Options) *cobra.Command {
	var (
		kind     string
		settings []string
	)

	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a notifier",
		Long: "Adds a notification transport. Compiled-in kinds: " +
			strings.Join(notify.Kinds(), ", ") + ".\n\n" +
			"Events signpost emits: " + eventTypeList() + "\n\n" +
			"Examples:\n" +
			"  signpost notifier add ops-mail --kind smtp \\\n" +
			"    --set host=smtp.example.org --set from=signpost@example.org \\\n" +
			"    --set to=ops@example.org --set password=$SMTP_PASSWORD\n\n" +
			"  signpost notifier add ops-hook --kind webhook \\\n" +
			"    --set url=https://hooks.example.org/t/xxxx",
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

			cfg := notify.Config{Name: args[0], Kind: kind, Settings: parsed}

			var created server.NotifierResponse
			if err := client.Post(cmd.Context(), server.APIPrefix+"/notifiers", cfg, &created); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, created)
			}

			fmt.Fprintf(out, "Added notifier %q (%s).\n", created.Name, created.Kind)
			fmt.Fprintf(out, "\nSend a test notification with:\n  signpost notifier test %s\n", created.Name)

			return nil
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "notifier kind: "+strings.Join(notify.Kinds(), ", "))
	cmd.Flags().StringArrayVar(&settings, "set", nil, "setting as key=value, repeatable")

	if err := cmd.MarkFlagRequired("kind"); err != nil {
		panic(err)
	}

	return cmd
}

func newNotifierListCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List the configured notifiers",
		Long:    "Lists the notifiers. Credentials, and webhook URLs, are always redacted.",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var notifiers []server.NotifierResponse
			if err := client.Get(cmd.Context(), server.APIPrefix+"/notifiers", &notifiers); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, notifiers)
			}

			if len(notifiers) == 0 {
				fmt.Fprintln(out, "No notifiers configured. Events are still persisted, and will be")
				fmt.Fprintln(out, "delivered once a notifier is added.")

				return nil
			}

			t := newTable(out, "name", "kind", "settings")
			for _, n := range notifiers {
				t.row(n.Name, n.Kind, renderSettings(n.Settings))
			}

			return t.flush()
		},
	}
}

func newNotifierRemoveCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "remove <name>",
		Short:   "Remove a notifier",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var result server.TestResponse
			err = client.Do(cmd.Context(), "DELETE",
				server.APIPrefix+"/notifiers/"+args[0], nil, &result)
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", result.Message)

			return nil
		},
	}
}

func newNotifierTestCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "test <name>",
		Short: "Send a test notification",
		Long: "Delivers a test notification immediately and reports the outcome.\n\n" +
			"Sent directly rather than through the outbox, so the result is the transport's real\n" +
			"answer - a queued event would report success whether or not the relay works.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var result server.TestResponse
			err = client.Post(cmd.Context(), server.APIPrefix+"/notifiers/"+args[0]+"/test", nil, &result)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, result)
			}

			if !result.OK {
				fmt.Fprintf(cmd.ErrOrStderr(), "notifier %q: %s\n", args[0], result.Message)

				return errors.New("notifier test failed")
			}

			fmt.Fprintf(out, "notifier %q: %s\n", args[0], result.Message)

			return nil
		},
	}
}

// eventTypeList renders signpost's event taxonomy for the help text, so an
// operator configuring a notifier can see what it will receive.
func eventTypeList() string {
	types := app.EventTypes()

	names := make([]string, 0, len(types))
	for _, t := range types {
		names = append(names, string(t))
	}

	return strings.Join(names, ", ")
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
