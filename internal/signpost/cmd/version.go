package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/signpost/app"
	"github.com/adnoctem/netory/internal/signpost/server"
	"github.com/adnoctem/netory/pkg/notify"
	"github.com/adnoctem/netory/pkg/stamp"
)

// newVersionCommand builds `signpost version`.
//
// It reports the CLI's own build and, when a server is reachable, the server's
// too - along with what that server is serving. Those can differ: an operator
// can have an older binary in PATH than the one running as the service, and
// that mismatch is worth seeing rather than guessing at.
func newVersionCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: "Prints this binary's build information, and the running server's when one is reachable.\n\n" +
			"Works without a running server.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			stamps := stamp.New()

			// The server is optional. `version` must answer when the service
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
					payload["server"] = remote
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
				fmt.Fprintf(out, "\nserver:      not reachable on %s\n", opts.Socket)

				return nil
			}

			fmt.Fprintf(out, "\nserver %s\n", remote.Version)
			fmt.Fprintf(out, "  commit:    %s\n", remote.CommitSHA)
			fmt.Fprintf(out, "  built:     %s\n", remote.BuildDate)
			fmt.Fprintf(out, "  serving:   %s -> %s (%d routes, %d releases)\n",
				dash(remote.ServingAlias), dash(remote.ServingRelease),
				remote.ServingRoutes, remote.Releases)
			fmt.Fprintf(out, "  content:   %s\n", remote.ContentStore)

			if remote.Version != stamps.Version {
				fmt.Fprintf(out,
					"\nnote: this CLI (%s) and the running server (%s) are different builds\n",
					stamps.Version, remote.Version)
			}

			return nil
		},
	}
}
