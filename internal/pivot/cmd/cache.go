package cmd

import (
	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/pivot/server"
)

// newCacheCommand builds `pivot cache`.
//
// An operator who has just
// narrowed a rule, or fixed a route wrongly marked shared, needs a way to stop
// the cache serving what it cached under the old configuration - and the
// alternative is waiting out a TTL that may be hours.
func newCacheCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect and purge the response cache",
		Long: "Only routes explicitly marked cacheable are cached, for the TTL that route declares,\n" +
			"and the key always covers the client unless the route is marked shared.\n\n" +
			"That shared flag is the one setting here that can leak data between customers if it\n" +
			"is wrong: two clients with different backend permissions can get different responses\n" +
			"from one path, and pivot cannot tell. Purging is what undoes the mistake.",
	}

	cmd.AddCommand(newCachePurgeCommand(opts))

	return cmd
}

func newCachePurgeCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "purge",
		Short: "Remove every cached response",
		Long: "Removes all cached entries across every replica, since the cache is in Valkey.\n\n" +
			"This walks the keyspace, which is expensive on Valkey - an administrative operation,\n" +
			"not something to script on a timer.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return postMessage(cmd, opts, server.APIPrefix+"/cache/purge", nil, "POST")
		},
	}
}
