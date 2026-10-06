package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/internal/pivot/server"
)

// newClientCommand builds `pivot client`.
//
// More verbs than §3.1's add|list|remove, and each addition earns its place:
// a customer's credentials need rotating, a customer needs suspending without
// being deleted, and a customer's backend credentials and rate limit both
// change independently of the rest of the record.
func newClientCommand(opts *Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "client",
		Short:   "Manage the customers pivot issues credentials to",
		Aliases: []string{"clients"},
		Long: "A client is one customer. It holds pivot credentials, its own backend credentials,\n" +
			"an optional rule set of its own and a rate limit.\n\n" +
			"The two layers of the security model meet in this record: the rules are the first\n" +
			"layer, and the backend credentials carry the second. A customer granted too many\n" +
			"backend permissions on an allowed route gets that data, so the backend credentials\n" +
			"matter as much as the rules.",
	}

	cmd.AddCommand(
		newClientAddCommand(opts),
		newClientListCommand(opts),
		newClientGetCommand(opts),
		newClientRemoveCommand(opts),
		newClientRotateCommand(opts),
		newClientDisableCommand(opts),
		newClientEnableCommand(opts),
		newClientBackendCommand(opts),
		newClientLimitCommand(opts),
	)

	return cmd
}

// backendFlags are the flags that describe a backend credential, shared by
// `client add` and `client backend`.
type backendFlags struct {
	mode      string
	tokenPath string
	clientID  string
	secret    string
	scope     string
	username  string
	password  string
	header    string
	key       string
	keyPrefix string
}

// register adds the backend flags to a command.
func (b *backendFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&b.mode, "backend-mode", string(auth.BackendOAuth2),
		"how pivot authenticates to the backend: "+strings.Join(auth.BackendModes(), ", "))
	cmd.Flags().StringVar(&b.tokenPath, "backend-token-path", "/api/oauth/token",
		"the backend's token endpoint, for oauth2 mode")
	cmd.Flags().StringVar(&b.clientID, "backend-client-id", "", "oauth2 client id")
	cmd.Flags().StringVar(&b.secret, "backend-client-secret", "", "oauth2 client secret")
	cmd.Flags().StringVar(&b.scope, "backend-scope", "", "optional oauth2 scope")
	cmd.Flags().StringVar(&b.username, "backend-username", "", "http-basic username")
	cmd.Flags().StringVar(&b.password, "backend-password", "", "http-basic password")
	cmd.Flags().StringVar(&b.header, "backend-header", "", "api-key header name; defaults to Authorization")
	cmd.Flags().StringVar(&b.key, "backend-key", "", "api-key value")
	cmd.Flags().StringVar(&b.keyPrefix, "backend-key-prefix", "",
		`api-key prefix, for an API wanting "Bearer <key>" or "token <key>"`)
}

// config renders the flags as a backend configuration.
func (b *backendFlags) config() auth.BackendConfig {
	return auth.BackendConfig{
		Mode:         auth.BackendMode(b.mode),
		TokenPath:    b.tokenPath,
		ClientID:     b.clientID,
		ClientSecret: b.secret,
		Scope:        b.scope,
		Username:     b.username,
		Password:     b.password,
		Header:       b.header,
		Key:          b.key,
		KeyPrefix:    b.keyPrefix,
	}
}

func newClientAddCommand(opts *Options) *cobra.Command {
	var (
		backend   backendFlags
		burst     int
		perSecond float64
	)

	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a customer and print its credentials once",
		Long: "Creates a client, generates its pivot credentials, and prints the secret once.\n\n" +
			"The secret is stored only as a SHA-256 hash and cannot be recovered: a lost secret is\n" +
			"rotated, not retrieved. A store that could hand a credential back is a store whose\n" +
			"compromise hands over every credential.\n\n" +
			"Example, for a Shopware integration:\n" +
			"  pivot client add 'Acme GmbH' \\\n" +
			"    --backend-mode oauth2 \\\n" +
			"    --backend-client-id \"$SW_ID\" --backend-client-secret \"$SW_SECRET\" \\\n" +
			"    --burst 60 --per-second 2",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var created server.ClientResponse

			err = client.Post(cmd.Context(), server.APIPrefix+"/clients", server.ClientRequest{
				Name:      args[0],
				Backend:   backend.config(),
				Burst:     burst,
				PerSecond: perSecond,
			}, &created)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, created)
			}

			fmt.Fprintf(out, "Added client %q.\n\n", created.Name)
			fmt.Fprintf(out, "  client_id:     %s\n", created.ID)
			fmt.Fprintf(out, "  client_secret: %s\n\n", created.Secret)
			fmt.Fprintln(out, "The secret is shown once and is not recoverable. Store it now.")
			fmt.Fprintf(out, "\nThe customer authenticates against pivot's own token endpoint with these,\n"+
				"exactly as it would against the backend's.\n")

			return nil
		},
	}

	backend.register(cmd)
	cmd.Flags().IntVar(&burst, "burst", 0,
		"requests the client may take at once; 0 uses the instance default")
	cmd.Flags().Float64Var(&perSecond, "per-second", 0,
		"sustained requests per second; 0 uses the instance default")

	return cmd
}

func newClientListCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List the configured customers",
		Aliases: []string{"ls"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var clients []server.ClientResponse
			if err := client.Get(cmd.Context(), server.APIPrefix+"/clients", &clients); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, clients)
			}

			if len(clients) == 0 {
				fmt.Fprintln(out, "no clients configured")

				return nil
			}

			t := newTable(out, "client id", "name", "backend", "rate limit", "rules", "state")
			for _, c := range clients {
				state := "active"
				if c.Disabled {
					state = "disabled"
				}

				t.row(c.ID, c.Name, c.Backend["mode"], c.RateLimit, c.Rules, state)
			}

			return t.flush()
		},
	}
}

func newClientGetCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "get <client-id>",
		Short: "Show one customer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var found server.ClientResponse
			err = client.Get(cmd.Context(), server.APIPrefix+"/clients/"+args[0], &found)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, found)
			}

			fmt.Fprintf(out, "%s (%s)\n", found.Name, found.ID)

			t := newTable(out, "  key", "value")
			t.row("  rate limit", found.RateLimit)
			t.row("  rules", found.Rules)
			t.row("  created", found.CreatedAt.Format("2006-01-02 15:04"))
			t.row("  created by", found.CreatedBy)

			for _, key := range sortedKeys(found.Backend) {
				t.row("  backend."+key, found.Backend[key])
			}

			return t.flush()
		},
	}
}

func newClientRemoveCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:     "remove <client-id>",
		Short:   "Delete a customer and revoke its tokens",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return postMessage(cmd, opts, server.APIPrefix+"/clients/"+args[0], nil, "DELETE")
		},
	}
}

func newClientRotateCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <client-id>",
		Short: "Issue a new secret for a customer",
		Long: "Replaces the client secret and prints the new one once.\n\n" +
			"The old secret stops working immediately. Access tokens already issued under it keep\n" +
			"working until they expire, which is the honest behaviour - a token is a separate\n" +
			"credential with its own lifetime. Use `pivot token revoke` to withdraw one early, or\n" +
			"`pivot client disable` to stop everything at once.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := opts.client()
			if err != nil {
				return err
			}

			var rotated server.ClientResponse
			err = client.Post(cmd.Context(),
				server.APIPrefix+"/clients/"+args[0]+"/rotate", nil, &rotated)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if opts.JSON {
				return printJSON(out, rotated)
			}

			fmt.Fprintf(out, "  client_id:     %s\n", args[0])
			fmt.Fprintf(out, "  client_secret: %s\n\n", rotated.Secret)
			fmt.Fprintln(out, "The old secret no longer works. Tokens issued under it expire on their own;")
			fmt.Fprintln(out, "run `pivot token list --client "+args[0]+"` to see them.")

			return nil
		},
	}
}

func newClientDisableCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "disable <client-id>",
		Short: "Suspend a customer and revoke its tokens",
		Long: "Stops a client authenticating without deleting it, so it can be restored without\n" +
			"reissuing credentials. Its tokens are revoked too - a suspended client that kept\n" +
			"working until its tokens expired is not what \"disabled\" means.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return postMessage(cmd, opts,
				server.APIPrefix+"/clients/"+args[0]+"/disable", nil, "POST")
		},
	}
}

func newClientEnableCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "enable <client-id>",
		Short: "Restore a suspended customer",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return postMessage(cmd, opts,
				server.APIPrefix+"/clients/"+args[0]+"/enable", nil, "POST")
		},
	}
}

func newClientBackendCommand(opts *Options) *cobra.Command {
	var backend backendFlags

	cmd := &cobra.Command{
		Use:   "backend <client-id>",
		Short: "Replace a customer's backend credentials",
		Long: "Replaces the credentials pivot uses on this customer's behalf.\n\n" +
			"The change takes effect on the next request: the replica drops the backend token it\n" +
			"fetched with the old credentials rather than using it until it expires, which would\n" +
			"look like a rotation that did not take.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return postMessage(cmd, opts,
				server.APIPrefix+"/clients/"+args[0]+"/backend", backend.config(), "POST")
		},
	}

	backend.register(cmd)

	return cmd
}

func newClientLimitCommand(opts *Options) *cobra.Command {
	var (
		burst     int
		perSecond float64
	)

	cmd := &cobra.Command{
		Use:   "limit <client-id>",
		Short: "Set a customer's rate limit",
		Long: "Sets the token bucket for one customer.\n\n" +
			"The bucket is a burst plus a sustained rate: --burst is how many requests the client\n" +
			"may take at once, --per-second what it may sustain. A fractional rate is meaningful,\n" +
			"so 0.5 is one request every two seconds. Both zero means the instance default.\n\n" +
			"The existing bucket is cleared, so a raised limit takes effect now rather than after\n" +
			"the old one refills at the old rate.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return postMessage(cmd, opts, server.APIPrefix+"/clients/"+args[0]+"/limit",
				server.LimitRequest{Burst: burst, PerSecond: perSecond}, "POST")
		},
	}

	cmd.Flags().IntVar(&burst, "burst", 0, "requests the client may take at once; 0 is the default")
	cmd.Flags().Float64Var(&perSecond, "per-second", 0, "sustained requests per second")

	return cmd
}

// postMessage issues a request whose response is a one-line result.
func postMessage(cmd *cobra.Command, opts *Options, path string, body any, method string) error {
	client, err := opts.client()
	if err != nil {
		return err
	}

	var result server.TestResponse
	if err := client.Do(cmd.Context(), method, path, body, &result); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if opts.JSON {
		return printJSON(out, result)
	}

	if result.Message == "" {
		result.Message = "done"
	}

	fmt.Fprintln(out, result.Message)

	return nil
}
