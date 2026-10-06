package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/signpost/server"
)

// newAliasCommand builds `signpost alias`.
func newAliasCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alias",
		Short: "Point aliases at releases",
		Long: "An alias is a movable name for one release - `latest`, `stable`, or whatever an\n" +
			"install URL should be stable across.\n\n" +
			"Moving an alias is the atomic swap that makes publishing atomic: the release and all\n" +
			"its content exist before any alias names them, so a client following an alias always\n" +
			"lands on something complete.",
	}

	cmd.AddCommand(
		newAliasSetCommand(opts),
		newAliasListCommand(opts),
		newAliasRemoveCommand(opts),
	)

	return cmd
}

func newAliasSetCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "set <alias> <release>",
		Short: "Point an alias at a release",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var alias server.AliasResponse
			err = client.Put(cmd.Context(), server.APIPrefix+"/aliases/"+args[0],
				server.AliasRequest{Release: args[1]}, &alias)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, alias)
			}

			fmt.Fprintf(out, "%s now points at %s\n", alias.Name, alias.Release)

			if alias.Previous != "" {
				fmt.Fprintf(out, "  rollback would return it to %s\n", alias.Previous)
			}

			return nil
		},
	}
}

func newAliasListCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List the configured aliases",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var aliases []server.AliasResponse
			if err := client.Get(cmd.Context(), server.APIPrefix+"/aliases", &aliases); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, aliases)
			}

			if len(aliases) == 0 {
				fmt.Fprintln(out, "no aliases configured")

				return nil
			}

			t := newTable(out, "alias", "release", "rollback to", "updated", "by")
			for _, alias := range aliases {
				name := alias.Name
				if alias.Serving {
					name = "* " + name
				}

				t.row(name, alias.Release, dash(alias.Previous),
					alias.UpdatedAt.Format("2006-01-02 15:04"), alias.UpdatedBy)
			}

			if err := t.flush(); err != nil {
				return err
			}

			fmt.Fprintln(out, "\n* is the alias the unversioned public routes are served from")

			return nil
		},
	}
}

func newAliasRemoveCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "remove <alias>",
		Short:   "Delete an alias",
		Aliases: []string{"rm"},
		Long: "Deletes an alias. The releases it pointed at are untouched and stay reachable on\n" +
			"their versioned paths.\n\n" +
			"The serving alias cannot be removed while it is the serving alias: point serve.alias\n" +
			"elsewhere first, so stopping an install URL is always a deliberate two-step act.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			if err := client.Delete(cmd.Context(), server.APIPrefix+"/aliases/"+args[0]); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", args[0])

			return nil
		},
	}
}
