package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/internal/protean/server"
)

// newHostCommand builds `protean host`.
func newHostCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "host",
		Short:   "Manage the names protean keeps updated",
		Aliases: []string{"hosts"},
	}

	cmd.AddCommand(
		newHostAddCommand(opts),
		newHostListCommand(opts),
		newHostRemoveCommand(opts),
	)

	return cmd
}

func newHostAddCommand(opts *Options) *cobra.Command {
	var (
		providerName string
		noIPv4       bool
		noIPv6       bool
		ttl          time.Duration
	)

	cmd := &cobra.Command{
		Use:   "add <hostname>",
		Short: "Add a host",
		Long: "Adds a name for protean to keep updated.\n\n" +
			"Both A and AAAA records are managed by default. IPv6 matters especially on DS-Lite\n" +
			"connections, where the IPv4 address protean observes belongs to the ISP's carrier-grade\n" +
			"NAT rather than to the subscriber.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			manageA, manageAAAA := !noIPv4, !noIPv6
			if !manageA && !manageAAAA {
				return errors.New("--no-ipv4 and --no-ipv6 together would leave nothing to update")
			}

			req := server.HostRequest{
				Name:       args[0],
				Provider:   providerName,
				ManageA:    &manageA,
				ManageAAAA: &manageAAAA,
			}

			if ttl > 0 {
				req.TTL = ttl.String()
			}

			var host app.Host
			if err := client.Post(cmd.Context(), server.APIPrefix+"/hosts", req, &host); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, host)
			}

			fmt.Fprintf(out, "Added %s via provider %q.\n", host.Name, host.Provider)
			fmt.Fprintf(out, "\nIssue a token for it with:\n  protean token create %s\n", host.Name)

			return nil
		},
	}

	cmd.Flags().StringVar(&providerName, "provider", "", "name of the provider instance that owns this zone")
	cmd.Flags().BoolVar(&noIPv4, "no-ipv4", false, "do not manage the A record")
	cmd.Flags().BoolVar(&noIPv6, "no-ipv6", false, "do not manage the AAAA record")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "record TTL; zero uses the provider default")

	if err := cmd.MarkFlagRequired("provider"); err != nil {
		panic(err)
	}

	return cmd
}

func newHostListCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List the configured hosts",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var hosts []app.Host
			if err := client.Get(cmd.Context(), server.APIPrefix+"/hosts", &hosts); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, hosts)
			}

			if len(hosts) == 0 {
				fmt.Fprintln(out, "No hosts configured. Add one with `protean host add`.")

				return nil
			}

			t := newTable(out, "name", "provider", "families", "last ipv4", "last ipv6", "last update")
			for _, host := range hosts {
				t.row(
					host.Name,
					host.Provider,
					families(host),
					dash(host.LastIPv4),
					dash(host.LastIPv6),
					lastUpdate(host),
				)
			}

			return t.flush()
		},
	}
}

func newHostRemoveCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <hostname>",
		Short: "Remove a host and revoke its tokens",
		Long: "Removes a host. Its tokens are revoked at the same time, so a credential cannot\n" +
			"outlive the host it was scoped to.\n\n" +
			"The DNS records themselves are left alone: protean owns no DNS data, and deleting a\n" +
			"record an operator may still want is not its decision to make.",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			if err := client.Delete(cmd.Context(), server.APIPrefix+"/hosts/"+args[0]); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(),
				"Removed %s and revoked its tokens.\nThe DNS records at the provider were left unchanged.\n",
				args[0])

			return nil
		},
	}
}

// families renders which record types a host manages.
func families(host app.Host) string {
	switch {
	case host.ManageA && host.ManageAAAA:
		return "A,AAAA"
	case host.ManageA:
		return "A"
	case host.ManageAAAA:
		return "AAAA"
	default:
		return "none"
	}
}

// lastUpdate renders when a host was last written, as an age.
//
// An age rather than a timestamp: "4m ago" answers "is this client still
// updating?" at a glance, which is the question an operator running `host list`
// actually has.
func lastUpdate(host app.Host) string {
	if host.LastUpdateAt.IsZero() {
		return "never"
	}

	return shortDuration(time.Since(host.LastUpdateAt)) + " ago"
}

// shortDuration renders a duration compactly.
func shortDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
