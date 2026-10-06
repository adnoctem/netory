// Package server is pivot's two listeners and the request pipeline between
// them.
//
// The split is the security model. The proxy listener faces customers and is
// read-only by construction: §10.1 settled that no customer will ever have
// write access, so the forwardable method set is fixed in code and no rule set
// can widen it. The admin listener is a Unix domain socket whose file
// permissions are the authorization, and because all state is in Valkey, a
// change made through one replica's socket applies to every replica.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/pkg/admin"
	"github.com/adnoctem/netory/pkg/forwarded"
	"github.com/adnoctem/netory/pkg/log"
)

// Timeouts for the proxy listener.
//
// The write timeout is the generous one: pivot is waiting on a backend it does
// not control, and cutting a response off because the backend was slow would
// turn somebody else's latency into pivot's failure. The read timeouts are
// tight, because a request is a path, some headers and at most a search body.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 120 * time.Second
	idleTimeout       = 90 * time.Second
)

// maxHeaderBytes bounds request headers on the proxy listener.
const maxHeaderBytes = 64 << 10

// MaxRequestBodyBytes bounds a forwarded request body.
//
// A search query is kilobytes. The bound exists because the body is read into
// memory to be hashed for the cache key and replayed on the forward leg, and
// an unbounded one would be a memory cost an authenticated customer could
// choose.
const MaxRequestBodyBytes = 4 << 20 // 4 MiB

// MaxResponseBodyBytes bounds a backend response pivot will buffer.
//
// It applies only to a route marked cacheable, because buffering is what
// caching and coalescing need - both want the whole body, and a stream can be
// sent to one reader. Every other route is copied straight through with no
// size limit, so a large export works; see Server.stream.
//
// A cacheable route whose response exceeds this is reported rather than served
// uncached: the operator asked for it to be cached and it never will be, which
// is a configuration mistake worth hearing about.
const MaxResponseBodyBytes = 32 << 20 // 32 MiB

// Server runs pivot's proxy and admin listeners.
type Server struct {
	state     *app.State
	log       *log.Logger
	forwarded *forwarded.Resolver

	// concurrency and coalescer are per replica, as §7.1 specifies.
	concurrency *Concurrency
	coalescer   *Coalescer

	// aggregator collects the denials, refusals and failures that §8.3 wants
	// reported as aggregates rather than per request.
	aggregator *Aggregator

	// backend is the HTTP client for the forward leg.
	backend *http.Client

	proxy *http.Server
	admin *admin.Server
}

// New builds the server from application state.
//
// It takes a context because it reads the settings document to size the
// concurrency limiter, and that is a store call like any other.
func New(ctx context.Context, state *app.State) (*Server, error) {
	if state == nil {
		return nil, errors.New("server: application state is required")
	}

	settings, err := state.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}

	s := &Server{
		state:       state,
		log:         state.Log,
		forwarded:   forwarded.NewResolver(state.Config.TrustedProxies),
		concurrency: NewConcurrency(settings.BackendConcurrency, DefaultAcquireTimeout),
		coalescer:   NewCoalescer(),
		aggregator:  NewAggregator(state),
		backend: &http.Client{
			Timeout: state.Config.BackendTimeout,

			// Redirects are not followed. A backend that redirects is sending
			// the client somewhere pivot's rules never evaluated, and
			// following it would forward pivot's credentials to whatever
			// Location said - which on a compromised or misconfigured backend
			// is a credential exfiltration primitive.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	s.proxy = &http.Server{
		Addr:              state.Config.Listen,
		Handler:           s.proxyHandler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,

		// net/http logs its own errors to the standard logger by default,
		// which would bypass the structured log entirely.
		ErrorLog: slog.NewLogLogger(state.Log.Handler(), slog.LevelWarn),
	}

	adminServer, err := admin.NewServer(admin.ServerOptions{
		Path:    state.Config.Socket,
		Handler: s.adminHandler(),
		Logger:  state.Log,
	})
	if err != nil {
		return nil, err
	}

	s.admin = adminServer

	return s, nil
}

// Start brings up both listeners and blocks until ctx is cancelled or a
// listener fails.
func (s *Server) Start(ctx context.Context) error {
	s.aggregator.Start(ctx)

	errs := make(chan error, 2)

	go func() {
		if err := s.serveProxy(); err != nil {
			errs <- fmt.Errorf("proxy listener: %w", err)

			return
		}

		errs <- nil
	}()

	go func() {
		if err := s.admin.Serve(); err != nil {
			errs <- fmt.Errorf("admin listener: %w", err)

			return
		}

		errs <- nil
	}()

	select {
	case <-ctx.Done():
		return s.Shutdown()
	case err := <-errs:
		// One listener failed, so the other is shut down too: a running admin
		// socket with no proxy - or the reverse - is a half-working replica
		// that a load balancer would keep sending traffic to.
		if shutdownErr := s.Shutdown(); shutdownErr != nil {
			return errors.Join(err, shutdownErr)
		}

		return err
	}
}

// serveProxy serves the customer-facing listener, with TLS when configured.
func (s *Server) serveProxy() error {
	cfg := s.state.Config

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}

	if cfg.TLS.Enabled() {
		s.log.Info("proxy listening with native TLS", "addr", cfg.Listen)

		// TLS 1.2 is the floor. It matters: customers authenticate with a
		// bearer token or Basic credentials on every request, so the
		// transport is the only thing protecting a credential that travels
		// continuously.
		s.proxy.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}

		if err := s.proxy.ServeTLS(listener, cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	}

	s.log.Info("proxy listening in plain HTTP, expecting a reverse proxy or ingress to terminate TLS",
		"addr", cfg.Listen)

	if err := s.proxy.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

// Shutdown stops both listeners, giving in-flight requests the configured
// grace period.
//
// It builds its own context rather than taking one. Start calls this when its
// own context is cancelled, which is to say already expired - inheriting it
// would make the grace period zero and cut off every proxied request mid
// flight, which on a rolling deployment is a burst of errors the customer
// sees as pivot's.
//
//nolint:contextcheck // detaching from the cancelled context is the point
func (s *Server) Shutdown() error {
	grace := s.state.Config.ShutdownGrace
	if grace <= 0 {
		grace = time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()

	var errs []error

	// The admin socket goes first, so no administrative change lands while
	// the replica is winding down.
	if err := s.admin.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}

	if err := s.proxy.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errs = append(errs, fmt.Errorf("shut down the proxy listener: %w", err))
	}

	// The aggregator flushes what it has collected, so a shutdown does not
	// discard the incident reports for the window it was in the middle of.
	s.aggregator.Stop()

	return errors.Join(errs...)
}

// AdminSocket returns the admin socket path, for the startup log line.
func (s *Server) AdminSocket() string { return s.admin.Path() }

// ProxyHandler exposes the proxy mux for tests, which exercise the pipeline
// without binding a port.
func (s *Server) ProxyHandler() http.Handler { return s.proxyHandler() }

// AdminHandler exposes the admin mux for tests.
func (s *Server) AdminHandler() http.Handler { return s.adminHandler() }

// Concurrency exposes the backend limiter, for `config view`.
func (s *Server) Concurrency() *Concurrency { return s.concurrency }

// Coalescer exposes the coalescer, for `config view`.
func (s *Server) Coalescer() *Coalescer { return s.coalescer }
