// Package server is protean's two listeners.
//
// The split is the heart of the security model. The update API faces the
// network and authenticates every request with a per-host token; the admin API
// is a Unix domain socket whose file permissions are the authorization. There
// is no remote administration, so there is nothing remote to authenticate
// against.
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

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/pkg/admin"
	"github.com/adnoctem/netory/pkg/log"
)

// Timeouts for the network-facing listener.
//
// A dynDNS update is a small GET; nothing legitimate needs long. These exist
// because the listener is public: without them a handful of idle connections
// can hold server resources indefinitely.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
)

// Server runs protean's update and admin listeners.
type Server struct {
	state   *app.State
	log     *log.Logger
	source  *SourceResolver
	limiter *Limiter

	update *http.Server
	admin  *admin.Server
}

// New builds the server from application state.
func New(state *app.State) (*Server, error) {
	if state == nil {
		return nil, errors.New("server: application state is required")
	}

	s := &Server{
		state:   state,
		log:     state.Log,
		source:  NewSourceResolver(state.Config),
		limiter: NewLimiter(state.RateLimit),
	}

	s.update = &http.Server{
		Addr:              state.Config.Listen,
		Handler:           s.updateHandler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,

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

// updateHandler builds the network-facing mux.
//
// Only the DynDNS2 path and a health endpoint are served. Anything else is a
// 404 with no body: an endpoint that is not part of the protocol has no
// business existing on a public listener, and listing what does exist only
// helps someone mapping the service.
func (s *Server) updateHandler() http.Handler {
	mux := http.NewServeMux()

	// Both methods, because clients differ: most use GET, a few POST.
	mux.HandleFunc("GET "+UpdatePath, s.handleUpdate)
	mux.HandleFunc("POST "+UpdatePath, s.handleUpdate)

	// A liveness endpoint that touches neither the database nor a provider, so
	// it answers while the service is degraded and reports the process itself.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	return mux
}

// Start brings up both listeners and blocks until ctx is cancelled or a
// listener fails.
func (s *Server) Start(ctx context.Context) error {
	errs := make(chan error, 2)

	go func() {
		if err := s.serveUpdate(); err != nil {
			errs <- fmt.Errorf("update listener: %w", err)

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
		// One listener failed. The other is shut down too, because a running
		// admin socket with no update API - or the reverse - is a half-working
		// service that looks healthy.
		if shutdownErr := s.Shutdown(); shutdownErr != nil {
			return errors.Join(err, shutdownErr)
		}

		return err
	}
}

// serveUpdate serves the network listener, with TLS when configured.
func (s *Server) serveUpdate() error {
	cfg := s.state.Config

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}

	if cfg.TLS.Enabled() {
		s.log.Info("update API listening with native TLS", "addr", cfg.Listen)

		// TLS 1.2 is the floor. Going lower would matter here: the token
		// travels in a Basic auth header on every request, so the transport is
		// the only thing protecting it.
		s.update.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}

		if err := s.update.ServeTLS(listener, cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	}

	s.log.Info("update API listening in plain HTTP, expecting a reverse proxy to terminate TLS",
		"addr", cfg.Listen)

	if err := s.update.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

// Shutdown stops both listeners, giving in-flight requests the configured
// grace period.
//
// It deliberately starts from context.Background() rather than taking a
// context from its caller. Start calls this when its own context is cancelled,
// which is to say already expired - inheriting it would make the grace period
// zero and drop every in-flight update at exactly the moment a graceful
// shutdown is wanted.
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

	// The admin socket goes first, so no new administrative change lands while
	// the service is winding down.
	if err := s.admin.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}

	if err := s.update.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errs = append(errs, fmt.Errorf("shut down the update listener: %w", err))
	}

	return errors.Join(errs...)
}

// AdminSocket returns the admin socket path, for the startup log line.
func (s *Server) AdminSocket() string { return s.admin.Path() }
