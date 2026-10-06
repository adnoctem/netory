package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/server"
	"github.com/adnoctem/netory/pkg/notify"
	"github.com/adnoctem/netory/pkg/stamp"
)

// newVersionCommand builds `pivot version`.
//
// It reports this binary's build and, when a replica is reachable, that
// replica's - including which replica answered and what rule version it is
// serving. On a multi-replica deployment those two are the questions that
// matter: a CLI older than the replicas is one thing, and two replicas
// serving different rule versions is another.
func newVersionCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: "Prints this binary's build information, and the answering replica's when one is\n" +
			"reachable.\n\nWorks without a running server.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			stamps := stamp.New()

			// The replica is optional. `version` must answer when the service
			// is down, which is frequently exactly when it is run.
			var remote *server.MetaResponse
			if client, err := opts.client(); err == nil {
				var meta server.MetaResponse
				if err := client.Get(cmd.Context(), server.APIPrefix+"/meta", &meta); err == nil {
					remote = &meta
				}
			}

			if opts.JSON {
				payload := map[string]any{
					"cli":       stamps,
					"notifiers": notify.Kinds(),
				}
				if remote != nil {
					payload["replica"] = remote
				}

				encoder := json.NewEncoder(out)
				encoder.SetIndent("", "  ")

				return encoder.Encode(payload)
			}

			fmt.Fprintf(out, "%s %s\n", app.Name, stamps.Version)
			fmt.Fprintf(out, "  commit:    %s (%s)\n", stamps.CommitSHA, stamps.Branch)
			fmt.Fprintf(out, "  built:     %s\n", stamps.BuildDate)
			fmt.Fprintf(out, "  go:        %s\n", stamps.GoVersion)
			fmt.Fprintf(out, "  platform:  %s\n", stamps.Platform)
			fmt.Fprintf(out, "  notifiers: %s\n", strings.Join(notify.Kinds(), ", "))

			if remote == nil {
				fmt.Fprintf(out, "\nreplica:     not reachable on %s\n", opts.Socket)

				return nil
			}

			fmt.Fprintf(out, "\nreplica %s (%s)\n", remote.Replica, remote.Version)
			fmt.Fprintf(out, "  commit:    %s\n", remote.CommitSHA)
			fmt.Fprintf(out, "  built:     %s\n", remote.BuildDate)
			fmt.Fprintf(out, "  rules:     version %d\n", remote.RuleVersion)
			fmt.Fprintf(out, "  clients:   %d\n", remote.Clients)
			fmt.Fprintf(out, "  backend:   %s\n", dash(remote.Backend))

			if remote.Version != stamps.Version {
				fmt.Fprintf(out,
					"\nnote: this CLI (%s) and the replica that answered (%s) are different builds\n",
					stamps.Version, remote.Version)
			}

			return nil
		},
	}
}
