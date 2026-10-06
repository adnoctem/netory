// Package cmd is signpost's Cobra command tree.
//
// Commands follow Git-style noun then verb ordering - `signpost bundle
// publish`, not `signpost publish-bundle` - as §3.1 specifies.
//
// # Two kinds of command
//
// `bundle validate`, `secret generate` and `version` work without a running
// server: the first validates a file on disk, the second is how an operator
// produces a secret before there is anything to run, and the third must answer
// when the service is down. `server start` is the server. Everything else is a
// short-lived client of the admin socket, since the server is the only process
// that may open the database.
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

	"github.com/adnoctem/netory/internal/signpost/app"
	"github.com/adnoctem/netory/internal/signpost/config"
	"github.com/adnoctem/netory/pkg/admin"
	"github.com/adnoctem/netory/pkg/log"
)

// Options carries the global flags down to every subcommand.
type Options struct {
	// Socket is the admin socket path, overridable so an operator can reach a
	// server configured with a non-default one.
	Socket string

	// Timeout bounds an admin request.
	//
	// Longer than protean's default, because one of these requests uploads a
	// bundle: a 64 MiB publish over a socket is fast, but it is not instant,
	// and a timeout that fires mid-upload would leave an operator unsure
	// whether the release landed.
	Timeout time.Duration

	// JSON switches output from tables to JSON, for scripting.
	JSON bool
}

// DefaultTimeout bounds an admin request unless --timeout says otherwise.
const DefaultTimeout = 2 * time.Minute

// NewRootCommand builds the `signpost` command tree.
func NewRootCommand() *cobra.Command {
	opts := &Options{}

	cmd := &cobra.Command{
		Use:   app.Name,
		Short: "Public script router",
		Long: "signpost serves a bundle of scripts at configured URL paths, for the one-line install\n" +
			"pattern - `curl -fsSL https://example.org/install.sh | sh`.\n\n" +
			"The served bytes are executed verbatim by the client, unreviewed. Every other decision\n" +
			"follows from that: releases are immutable, publishing is an atomic alias swap, bundles\n" +
			"are validated whole, and scripts are served over HTTPS only.\n\n" +
			"Publishing is local only, over a Unix domain socket - there is no remote publishing API.",
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
		"path to the admin socket")
	cmd.PersistentFlags().DurationVar(&opts.Timeout, "timeout", DefaultTimeout,
		"how long to wait for the server to answer")
	cmd.PersistentFlags().BoolVar(&opts.JSON, "json", false,
		"print output as JSON instead of a table")

	cmd.AddCommand(
		newServerCommand(),
		newBundleCommand(opts),
		newAliasCommand(opts),
		newNotifierCommand(opts),
		newConfigCommand(opts),
		newOutboxCommand(opts),
		newSecretCommand(),
		newVersionCommand(opts),
	)

	return cmd
}

// client builds an admin client from the global flags.
func (o *Options) client() (*admin.Client, error) {
	// The environment is consulted so that an operator who has
	// SIGNPOST_SOCKET set for the server does not have to repeat it on every
	// command. An explicit flag still wins.
	socket := o.Socket
	if socket == config.DefaultSocket {
		cfg := config.Default()
		if err := cfg.ApplyEnv(); err == nil && cfg.Socket != "" {
			socket = cfg.Socket
		}
	}

	return admin.NewClient(admin.ClientOptions{Path: socket, Timeout: o.Timeout})
}

// newServerCommand builds `signpost server`.
func newServerCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the signpost server",
	}

	cmd.AddCommand(newServerStartCommand())

	return cmd
}

// newServerStartCommand builds `signpost server start`.
//
// This is the only command that opens the database, and the flags here are the
// bootstrap configuration - the values needed before the database exists. The
// runtime settings live in the database and are managed with `signpost config`.
func newServerStartCommand() *cobra.Command {
	var (
		listen         string
		socket         string
		database       string
		content        string
		tlsCert        string
		tlsKey         string
		trustedProxies string
		logLevel       string
		logFormat      string
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the public API and the admin socket",
		Long: "Starts the long-lived server. This is the only process that opens the database;\n" +
			"Badger holds an exclusive lock on its directory, so a second instance cannot start.\n\n" +
			"The secret is read from " + config.SecretEnv + " or " + config.SecretFileEnv + ".\n\n" +
			"signpost serves scripts over HTTPS only. Either configure --tls-cert and --tls-key, or\n" +
			"run behind a reverse proxy and declare it with --trusted-proxies: without one of the two,\n" +
			"signpost cannot confirm a request arrived encrypted and will refuse to serve.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := config.Default()

			// Precedence: defaults, then the environment, then flags. A flag
			// beating an environment variable is what an operator debugging a
			// container will expect.
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
			if flags.Changed("database") {
				cfg.Database = database
			}
			if flags.Changed("content") {
				cfg.Content = content
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

	cmd.Flags().StringVar(&listen, "listen", config.DefaultListen, "address for the public API")
	cmd.Flags().StringVar(&socket, "socket", config.DefaultSocket, "path for the admin socket")
	cmd.Flags().StringVar(&database, "database", config.DefaultDatabase, "directory for the database")
	cmd.Flags().StringVar(&content, "content", config.DefaultContent,
		"directory for the published script contents")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "TLS certificate file; enables native TLS")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "TLS key file; enables native TLS")
	cmd.Flags().StringVar(&trustedProxies, "trusted-proxies", "",
		"comma-separated CIDR prefixes whose X-Forwarded-* headers are honoured")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	cmd.Flags().StringVar(&logFormat, "log-format", "text", "log format: text or json")

	return cmd
}

// signalContext returns a context cancelled on SIGINT or SIGTERM.
//
// SIGTERM is what a container runtime and systemd send, and handling it is
// what turns a kill into a graceful shutdown: in-flight downloads finish, the
// outbox is left consistent, and the socket is unlinked. Cutting a download
// off mid-script is the one thing this service exists to prevent, so the
// graceful path matters more here than it usually does.
func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

// errShutdown is returned when the server stopped because it was asked to,
// which is not a failure.
var errShutdown = errors.New("shutdown")
