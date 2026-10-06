package cmd

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/pivot/server"
)

// newOutboxCommand builds `pivot outbox`.
//
// Not in the design document's command tree, but the outbox is the mechanism
// behind "nothing lost on restart" and an operator needs some way to see it.
// An alert that never arrived is exactly what someone goes looking for after an
// incident, and without this the only way to find it is to read the log.
func newOutboxCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "outbox",
		Short: "Inspect the notification outbox",
		Long: "Shows how many events are waiting for delivery and how many were abandoned.\n\n" +
			"Events are persisted before any delivery is attempted, so a relay outage delays\n" +
			"notifications rather than dropping them. An event that failed its retries is kept as\n" +
			"dead rather than deleted, because a notification that never arrived is worth being\n" +
			"able to find.",
	}

	cmd.AddCommand(newOutboxStatusCommand(opts))

	return cmd
}

func newOutboxStatusCommand(opts *Options) *cobra.Command {
	var (
		showDead    bool
		showPending bool
	)

	cmd := &cobra.Command{
		Use:     "status",
		Short:   "Show the outbox counts, and the entries with --pending or --dead",
		Aliases: []string{"ls", "list"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			path := server.APIPrefix + "/outbox"
			switch {
			case showDead:
				path += "?dead=true"
			case showPending:
				path += "?pending=true"
			}

			var status server.OutboxResponse
			if err := client.Get(cmd.Context(), path, &status); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, status)
			}

			fmt.Fprintf(out, "pending: %d\n", status.Pending)
			fmt.Fprintf(out, "dead:    %d\n", status.Dead)

			if status.Dead > 0 && !showDead {
				fmt.Fprintln(out, "\nRun with --dead to see the abandoned events.")
			}

			if status.Pending > 0 && !showPending && !showDead {
				fmt.Fprintln(out, "\nRun with --pending to see the events awaiting delivery.")
			}

			if len(status.Entries) == 0 {
				return nil
			}

			fmt.Fprintln(out)

			t := newTable(out, "id", "event", "subject", "attempts", "age", "last error")
			for _, entry := range status.Entries {
				t.row(
					entry.Event.ID,
					string(entry.Event.Type),
					dash(entry.Event.Subject),
					strconv.Itoa(entry.Attempts),
					shortDuration(time.Since(entry.Event.OccurredAt))+" ago",
					dash(entry.LastError),
				)
			}

			return t.flush()
		},
	}

	cmd.Flags().BoolVar(&showDead, "dead", false, "list the events that were abandoned after their retries")
	cmd.Flags().BoolVar(&showPending, "pending", false, "list the events still waiting for delivery")
	cmd.MarkFlagsMutuallyExclusive("dead", "pending")

	return cmd
}
