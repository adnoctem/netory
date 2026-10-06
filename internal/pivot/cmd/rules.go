package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/pivot/rules"
	"github.com/adnoctem/netory/internal/pivot/server"
	"github.com/adnoctem/netory/pkg/admin"
)

// newRulesCommand builds `pivot rules`.
//
// §3.1 drafted validate|list|test, which left no way to install a rule set -
// and without one the service cannot work at all, since a fresh pivot denies
// everything. `apply` is therefore added.
//
// It installs a document the operator supplies and nothing else. pivot used to
// ship a Shopware rule set as a `--preset`, and no longer does: a rule set is a
// statement about what one installation will serve, and one compiled into the
// binary is a statement nobody reviewed that is applied by a single command.
// The example lives in docs/examples/pivot/ instead, where it can be read and
// edited before it is applied.
func newRulesCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Validate, inspect and apply the path rules",
		Long: "Rules are an allow list and a deny list over method plus normalized path. Deny is\n" +
			"evaluated first, and a request matching neither is denied - a missing rule is never\n" +
			"an implicit permission.\n\n" +
			"There is a global rule set and, optionally, extra rules per client. They accumulate:\n" +
			"a client's rules can grant a path the global set does not and can add restrictions of\n" +
			"their own, but cannot reopen a path the global set denies. So \"what can this customer\n" +
			"reach\" is answered by reading two lists under a fixed precedence.\n\n" +
			"A fresh pivot has no allow rules and therefore denies everything, which is the right\n" +
			"default for a service whose job is to refuse.",
	}

	cmd.AddCommand(
		newRulesValidateCommand(opts),
		newRulesListCommand(opts),
		newRulesTestCommand(opts),
		newRulesApplyCommand(opts),
	)

	return cmd
}

func newRulesValidateCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "validate <file.yaml>",
		Short: "Check a rule document without a running server",
		Long: "Parses and compiles a rule document and reports what it would enforce.\n\n" +
			"Works without a running server, which is the point: this is the command that runs in\n" +
			"CI before a rule change is applied anywhere.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			document, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read %q: %w", args[0], err)
			}

			doc, err := rules.Parse(document)
			if err != nil {
				return err
			}

			set, err := rules.Compile(doc, rules.ScopeGlobal)
			if err != nil {
				return err
			}

			deny, allow, routes := set.Counts()

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, map[string]any{
					"valid":   true,
					"deny":    deny,
					"allow":   allow,
					"routes":  routes,
					"entries": set.Describe(),
				})
			}

			fmt.Fprintf(out, "%s is valid: %d deny, %d allow, %d cacheable route(s)\n",
				filepath.Base(args[0]), deny, allow, routes)

			if set.Empty() {
				fmt.Fprintln(out,
					"\nwarning: there are no allow rules, so this rule set denies every request")
			}

			fmt.Fprintln(out)

			for _, entry := range set.Describe() {
				fmt.Fprintf(out, "  %s\n", entry)
			}

			return nil
		},
	}
}

func newRulesListCommand(opts *Options) *cobra.Command {
	var document bool

	cmd := &cobra.Command{
		Use:     "list",
		Short:   "Show the rule set the answering replica is serving",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			path := server.APIPrefix + "/rules"
			if document {
				path += "?document=true"
			}

			var response server.RulesResponse
			if err := client.Get(cmd.Context(), path, &response); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, response)
			}

			if document {
				fmt.Fprint(out, response.Document)

				return nil
			}

			fmt.Fprintf(out, "rule version %d: %d deny, %d allow, %d cacheable route(s)\n\n",
				response.Version, response.Deny, response.Allow, response.Routes)

			for _, entry := range response.Entries {
				fmt.Fprintf(out, "  %s\n", entry)
			}

			if len(response.Entries) == 0 {
				fmt.Fprintln(out, "  (nothing: every request is denied)")
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&document, "yaml", false, "print the stored document instead of a summary")

	return cmd
}

func newRulesTestCommand(opts *Options) *cobra.Command {
	var (
		method   string
		clientID string
	)

	cmd := &cobra.Command{
		Use:   "test <path>",
		Short: "Evaluate a method and path against the active rules",
		Long: "Reports what the rules would do with a request, without sending anything to the\n" +
			"backend.\n\n" +
			"The normalized path is reported too, because the difference between what was typed\n" +
			"and what was matched is exactly what the rules layer depends on - a path pivot would\n" +
			"refuse as ambiguous is reported as such rather than silently cleaned.\n\n" +
			"Pass --client to evaluate against that customer's accumulated rules rather than the\n" +
			"global set alone.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var response server.RuleTestResponse

			err = client.Post(cmd.Context(), server.APIPrefix+"/rules/test",
				server.RuleTestRequest{Method: method, Path: args[0], ClientID: clientID},
				&response)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, response)
			}

			verdict := "DENIED"
			if response.Allowed {
				verdict = "ALLOWED"
			}

			fmt.Fprintf(out, "%s  %s %s\n", verdict, response.Method, response.Path)

			if response.Normalized {
				fmt.Fprintf(out, "  normalized from what you typed; the rules matched %q\n",
					response.Path)
			}

			fmt.Fprintf(out, "  outcome:   %s\n", response.Outcome)

			if response.Rule != "" {
				fmt.Fprintf(out, "  rule:      %s\n", response.Rule)
			} else {
				fmt.Fprintln(out, "  rule:      none matched, so deny-by-default applied")
			}

			if response.Cacheable {
				encrypted := ""
				if response.Encrypted {
					encrypted = ", encrypted"
				}

				fmt.Fprintf(out, "  cacheable: yes (ttl %s%s)\n", response.CacheTTL, encrypted)
			} else {
				fmt.Fprintln(out, "  cacheable: no")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&method, "method", "GET", "the method to evaluate")
	cmd.Flags().StringVar(&clientID, "client", "",
		"evaluate against this client's accumulated rules")

	return cmd
}

func newRulesApplyCommand(opts *Options) *cobra.Command {
	var (
		denyAll  bool
		clientID string
	)

	cmd := &cobra.Command{
		Use:   "apply [file.yaml]",
		Short: "Install a rule set, globally or for one customer",
		Long: "Stores a rule document and tells every replica to reload it.\n\n" +
			"The document is compiled before it is stored, so a rule set that does not compile is\n" +
			"never installed - storing one would leave every replica failing its next reload and\n" +
			"serving whatever it had, which is a change that appears to have worked and did not.\n\n" +
			"pivot ships no rule set of its own. Example documents, including a complete read-only\n" +
			"set for the Shopware 6 Admin API, are in docs/examples/pivot/ - copy one, read it, and\n" +
			"edit it before applying it.\n\n" +
			"--deny-all applies a rule set that permits nothing, without a file. It is how an\n" +
			"instance is turned off without stopping it: customers' credentials and rate-limit\n" +
			"buckets survive, and every replica follows within a second.\n\n" +
			"Examples:\n" +
			"  pivot rules apply ./shopware-readonly.yaml\n" +
			"  pivot rules apply ./acme-extra.yaml --client 9f2c1d…\n" +
			"  pivot rules apply --deny-all",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var (
				document []byte
				err      error
			)

			switch {
			case denyAll && len(args) > 0:
				return errors.New("pass a file or --deny-all, not both")

			case denyAll:
				document, err = rules.Encode(rules.EmptyDocument())
				if err != nil {
					return err
				}

			case len(args) == 1:
				document, err = os.ReadFile(args[0])
				if err != nil {
					return fmt.Errorf("read %q: %w", args[0], err)
				}

			default:
				return errors.New(
					"pass a rule document, or --deny-all to permit nothing; " +
						"example documents are in docs/examples/pivot/")
			}

			// Compiled here as well as in the replica. The local pass gives
			// immediate feedback on a file the operator just wrote; the
			// replica's is the one that is trusted, since the CLI runs
			// outside its control.
			doc, err := rules.Parse(document)
			if err != nil {
				return err
			}

			scope := rules.ScopeGlobal
			if clientID != "" {
				scope = rules.ScopeClient
			}

			if _, err := rules.Compile(doc, scope); err != nil {
				return err
			}

			client, err := opts.client()
			if err != nil {
				return err
			}

			fields := map[string]string{}
			if clientID != "" {
				fields[server.FieldClient] = clientID
			}

			name := "rules.yaml"
			if len(args) == 1 {
				name = filepath.Base(args[0])
			}

			var response server.RulesResponse

			err = client.PostMultipart(cmd.Context(), server.APIPrefix+"/rules", fields,
				[]admin.Upload{{Field: server.FieldRules, Filename: name, Content: document}},
				&response)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, response)
			}

			target := "globally"
			if clientID != "" {
				target = "for client " + clientID
			}

			fmt.Fprintf(out, "applied %s: rule version %d, %d deny, %d allow, %d cacheable route(s)\n",
				target, response.Version, response.Deny, response.Allow, response.Routes)
			fmt.Fprintln(out, "every replica reloads within its poll interval, and sooner than that "+
				"if it heard the announcement")

			return nil
		},
	}

	cmd.Flags().BoolVar(&denyAll, "deny-all", false,
		"apply a rule set that permits nothing, without a file")
	cmd.Flags().StringVar(&clientID, "client", "",
		"apply as this client's own additional rules rather than globally")

	return cmd
}
