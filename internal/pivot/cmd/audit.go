package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/server"
)

// newAuditCommand builds `pivot audit`.
//
// pivot stores the low-volume half of its audit trail - administrative
// actions and aggregated security outcomes - itself, and this is how it is
// read. A trail nothing can read is a trail nobody will consult.
func newAuditCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Read the audit trail pivot stores itself",
		Long: "Shows the administrative actions and security-relevant outcomes pivot keeps in\n" +
			"Valkey, newest first.\n\n" +
			"This is the low-volume half of the trail. The per-request log - client, method,\n" +
			"normalized path, matched rule, status, latency - goes to the structured log instead,\n" +
			"where the volume and the retention belong to the operator's log pipeline: pivot\n" +
			"cannot enforce a retention period on records that leave the process, and it does not\n" +
			"pretend to.\n\n" +
			"What it does enforce is the retention of these records, which carry a TTL from\n" +
			"audit.retention - ninety days by default.",
	}

	cmd.AddCommand(newAuditListCommand(opts))

	return cmd
}

func newAuditListCommand(opts *Options) *cobra.Command {
	var kind string

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List the stored audit records, newest first",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			path := server.APIPrefix + "/audit"
			if kind != "" {
				path += "?kind=" + urlQueryEscape(kind)
			}

			var records []app.AuditRecord
			if err := client.Get(cmd.Context(), path, &records); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, records)
			}

			if len(records) == 0 {
				fmt.Fprintln(out, "no audit records stored")

				return nil
			}

			t := newTable(out, "when", "kind", "action", "actor", "subject", "detail", "replica")
			for _, record := range records {
				t.row(
					record.At.Format("2006-01-02 15:04:05"),
					string(record.Kind),
					record.Action,
					record.Actor,
					dash(record.Subject),
					renderSettings(record.Detail),
					dash(record.Replica),
				)
			}

			return t.flush()
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "",
		"only this kind of record: admin or security")

	return cmd
}
