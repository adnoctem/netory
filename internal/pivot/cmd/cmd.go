// Package cmd is pivot's Cobra command tree.
//
// Commands follow Git-style noun then verb ordering, as its siblings do.
//
// # Two kinds of command
//
// `rules validate`, `secret generate` and `version` work without a running
// server. `server start` is the server. Everything else is a short-lived
// client of a replica's admin socket.
//
// # Which replica answers
//
// pivot runs several replicas, so a command reaches whichever one's socket it
// is pointed at - through `kubectl exec` or `docker exec` in practice. That
// matters in one direction only: every mutation goes to Valkey and is
// announced, so the change applies everywhere, but a read reports the
// answering replica's own view. `version` and `config view` therefore name the
// replica, because two replicas disagreeing is something an operator needs to
// be able to see rather than guess at.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/config"
	"github.com/adnoctem/netory/pkg/admin"
	"github.com/adnoctem/netory/pkg/log"
)

// Options carries the global flags down to every subcommand.
type Options struct {
	// Socket is the admin socket path of the replica to talk to.
	Socket string

	// Timeout bounds an admin request.
	Timeout time.Duration

	// JSON switches output from tables to JSON, for scripting.
	JSON bool
}

// DefaultTimeout bounds an admin request unless --timeout says otherwise.
const DefaultTimeout = 30 * time.Second

// NewRootCommand builds the `pivot` command tree.
func NewRootCommand() *cobra.Command {
	opts := &Options{}

	cmd := &cobra.Command{
		Use:   app.Name,
		Short: "Transparent API proxy",
		Long: "pivot sits between customers and a production API. It issues its own credentials,\n" +
			"authenticates to the backend on the customer's behalf, filters requests by path rules,\n" +
			"and protects the backend with rate limits, a concurrency cap and a response cache.\n\n" +
			"Two independent layers must both fail before a customer reaches data they should not\n" +
			"see: pivot's path rules, and the backend permissions of that customer's own backend\n" +
			"credentials. Neither is trusted to be sufficient alone.\n\n" +
			"pivot is read-only by construction. It forwards GET, HEAD and POST and nothing else,\n" +
			"and no rule set can change that.",
		SilenceErrors:     true,
		SilenceUsage:      true,
		TraverseChildren:  true,
		CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Usage()
			}

			return fmt.Errorf("unknown command %q", args[0])
		},
	}

	cmd.PersistentFlags().StringVar(&opts.Socket, "socket", config.DefaultSocket,
		"path to a replica's admin socket")
	cmd.PersistentFlags().DurationVar(&opts.Timeout, "timeout", DefaultTimeout,
		"how long to wait for the replica to answer")
	cmd.PersistentFlags().BoolVar(&opts.JSON, "json", false,
		"print output as JSON instead of a table")

	cmd.AddCommand(
		newServerCommand(),
		newClientCommand(opts),
		newTokenCommand(opts),
		newBackendCommand(opts),
		newRulesCommand(opts),
		newNotifierCommand(opts),
		newConfigCommand(opts),
		newOutboxCommand(opts),
		newAuditCommand(opts),
		newCacheCommand(opts),
		newSecretCommand(),
		newVersionCommand(opts),
	)

	return cmd
}

// client builds an admin client from the global flags.
func (o *Options) client() (*admin.Client, error) {
	// The environment is consulted so an operator who has PIVOT_SOCKET set
	// for the server does not have to repeat it on every command. An explicit
	// flag still wins.
	socket := o.Socket
	if socket == config.DefaultSocket {
		cfg := config.Default()
		if err := cfg.ApplyEnv(); err == nil && cfg.Socket != "" {
			socket = cfg.Socket
		}
	}

	return admin.NewClient(admin.ClientOptions{Path: socket, Timeout: o.Timeout})
}

// newServerCommand builds `pivot server`.
func newServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run a pivot replica",
	}

	cmd.AddCommand(newServerStartCommand())

	return cmd
}

// newServerStartCommand builds `pivot server start`.
//
// The flags here are the bootstrap configuration: the values needed before
// Valkey can be reached. Everything else lives in Valkey and is managed with
// `pivot config`, which is what makes a change on one replica apply to all.
func newServerStartCommand() *cobra.Command {
	var (
		listen         string
		socket         string
		valkey         string
		valkeyUser     string
		valkeyDB       int
		valkeyTLS      bool
		replica        string
		tlsCert        string
		tlsKey         string
		trustedProxies string
		backendTimeout time.Duration
		logLevel       string
		logFormat      string
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the proxy and the admin socket",
		Long: "Starts a replica. Several may run at once: all shared state is in Valkey, so there\n" +
			"is no lock to take and no consensus between them.\n\n" +
			"The secret is read from " + config.SecretEnv + " or " + config.SecretFileEnv + ", and every\n" +
			"replica must be given the same value - keys derived from it decrypt the backend\n" +
			"credentials in Valkey, so a replica with a different secret starts cleanly and then\n" +
			"fails every forward leg.\n\n" +
			"The Valkey password comes from " + config.ValkeyPasswordFileEnv + " or\n" +
			config.EnvPrefix + "VALKEY_PASSWORD; there is no flag for it, because a password on a\n" +
			"command line is a password in the process list.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config.Default()

			// Precedence: defaults, then the environment, then flags.
			if err := cfg.ApplyEnv(); err != nil {
				return err
			}

			flags := cmd.Flags()

			if flags.Changed("listen") {
				cfg.Listen = listen
			}
			if flags.Changed("socket") {
				cfg.Socket = socket
			}
			if flags.Changed("valkey") {
				cfg.Valkey.Address = splitComma(valkey)
			}
			if flags.Changed("valkey-username") {
				cfg.Valkey.Username = valkeyUser
			}
			if flags.Changed("valkey-db") {
				cfg.Valkey.DB = valkeyDB
			}
			if flags.Changed("valkey-tls") {
				cfg.Valkey.TLS = valkeyTLS
			}
			if flags.Changed("replica") {
				cfg.Replica = replica
			}
			if flags.Changed("tls-cert") {
				cfg.TLS.CertFile = tlsCert
			}
			if flags.Changed("tls-key") {
				cfg.TLS.KeyFile = tlsKey
			}
			if flags.Changed("trusted-proxies") {
				prefixes, err := config.ParseTrustedProxies(trustedProxies)
				if err != nil {
					return err
				}

				cfg.TrustedProxies = prefixes
			}
			if flags.Changed("backend-timeout") {
				cfg.BackendTimeout = backendTimeout
			}
			if flags.Changed("log-level") {
				level, ok := log.ParseLevel(logLevel)
				if !ok {
					return fmt.Errorf("--log-level %q is not one of debug, info, warn, error", logLevel)
				}

				cfg.LogLevel = level
			}
			if flags.Changed("log-format") {
				format, ok := log.ParseFormat(logFormat)
				if !ok {
					return fmt.Errorf("--log-format %q is not one of text, json", logFormat)
				}

				cfg.LogFormat = format
			}

			return runServer(cmd.Context(), cfg)
		},
	}

	cmd.Flags().StringVar(&listen, "listen", config.DefaultListen, "address for the proxy")
	cmd.Flags().StringVar(&socket, "socket", config.DefaultSocket, "path for this replica's admin socket")
	cmd.Flags().StringVar(&valkey, "valkey", config.DefaultValkeyAddress,
		"comma-separated Valkey addresses as host:port")
	cmd.Flags().StringVar(&valkeyUser, "valkey-username", "", "Valkey ACL username")
	cmd.Flags().IntVar(&valkeyDB, "valkey-db", 0, "Valkey logical database; ignored by a cluster")
	cmd.Flags().BoolVar(&valkeyTLS, "valkey-tls", false, "connect to Valkey over TLS")
	cmd.Flags().StringVar(&replica, "replica", "",
		"this replica's identity; defaults to the hostname, which on Kubernetes is the pod name")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "TLS certificate file; enables native TLS")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "TLS key file; enables native TLS")
	cmd.Flags().StringVar(&trustedProxies, "trusted-proxies", "",
		"comma-separated CIDR prefixes whose X-Forwarded-* headers are honoured")
	cmd.Flags().DurationVar(&backendTimeout, "backend-timeout", config.DefaultBackendTimeout,
		"how long one forward leg may take")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	cmd.Flags().StringVar(&logFormat, "log-format", "text", "log format: text or json")

	return cmd
}

// splitComma parses a comma-separated list, dropping empty entries.
func splitComma(raw string) []string {
	var out []string

	for _, entry := range splitAndTrim(raw) {
		if entry != "" {
			out = append(out, entry)
		}
	}

	return out
}

// signalContext returns a context cancelled on SIGINT or SIGTERM.
//
// SIGTERM is what Kubernetes sends before it removes a pod, and handling it is
// what turns a rolling deployment into a graceful one: in-flight proxied
// requests finish, outbox claims are released rather than left to their lease,
// and the socket is unlinked.
func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

// errShutdown is returned when the server stopped because it was asked to.
var errShutdown = errors.New("shutdown")
