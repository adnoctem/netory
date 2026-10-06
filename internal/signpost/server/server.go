// Package server is signpost's two listeners.
//
// The split is the security model. The public API faces the network, serves
// anonymously, and is read-only - there is no path on it that changes
// anything. The admin API is a Unix domain socket whose file permissions are
// the authorization, and it is where publishing happens. §2 calls this
// local-only publishing: there is no remote publishing API, so there is
// nothing remote to authenticate against and nothing remote to get wrong.
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

	"github.com/adnoctem/netory/internal/signpost/app"
	"github.com/adnoctem/netory/pkg/admin"
	"github.com/adnoctem/netory/pkg/forwarded"
	"github.com/adnoctem/netory/pkg/log"
)

// Timeouts for the network-facing listener.
//
// A script fetch is a small GET answered from memory; nothing legitimate needs
// long. These exist because the listener is public and anonymous: without them
// a handful of idle connections can hold server resources indefinitely, and
// signpost has no token to rate-limit on.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 60 * time.Second
)

// maxHeaderBytes bounds request headers on the public listener. The default is
// 1 MiB, which is generous for a service whose requests are a path and a
// User-Agent.
const maxHeaderBytes = 16 << 10

// Server runs signpost's public and admin listeners.
type Server struct {
	state     *app.State
	log       *log.Logger
	forwarded *forwarded.Resolver

	public *http.Server
	admin  *admin.Server
}

// New builds the server from application state.
func New(state *app.State) (*Server, error) {
	if state == nil {
		return nil, errors.New("server: application state is required")
	}

	s := &Server{
		state:     state,
		log:       state.Log,
		forwarded: forwarded.NewResolver(state.Config.TrustedProxies),
	}

	s.public = &http.Server{
		Addr:              state.Config.Listen,
		Handler:           s.publicHandler(),
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
	errs := make(chan error, 2)

	go func() {
		if err := s.servePublic(); err != nil {
			errs <- fmt.Errorf("public listener: %w", err)

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
		// admin socket with no public API - or the reverse - is a half-working
		// service that looks healthy.
		if shutdownErr := s.Shutdown(); shutdownErr != nil {
			return errors.Join(err, shutdownErr)
		}

		return err
	}
}

// servePublic serves the network listener, with TLS when configured.
func (s *Server) servePublic() error {
	cfg := s.state.Config

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}

	if cfg.TLS.Enabled() {
		s.log.Info("public API listening with native TLS", "addr", cfg.Listen)

		// TLS 1.2 is the floor. It matters here as much as anywhere in
		// netory: the response body is about to be executed by the client, so
		// the transport is the only thing standing between a network attacker
		// and arbitrary code on the user's machine.
		s.public.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}

		if err := s.public.ServeTLS(listener, cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	}

	s.log.Info("public API listening in plain HTTP, expecting a reverse proxy to terminate TLS",
		"addr", cfg.Listen)

	if err := s.public.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
// zero and cut off every in-flight download at exactly the moment a graceful
// shutdown is wanted. A client piping a half-received script into a shell is
// the specific thing that makes this worth getting right.
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

	// The admin socket goes first, so no publish lands while the service is
	// winding down.
	if err := s.admin.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}

	if err := s.public.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		errs = append(errs, fmt.Errorf("shut down the public listener: %w", err))
	}

	return errors.Join(errs...)
}

// AdminSocket returns the admin socket path, for the startup log line.
func (s *Server) AdminSocket() string { return s.admin.Path() }

// PublicHandler exposes the public mux for tests, which exercise the serving
// path without binding a port.
func (s *Server) PublicHandler() http.Handler { return s.publicHandler() }

// AdminHandler exposes the admin mux for tests.
func (s *Server) AdminHandler() http.Handler { return s.adminHandler() }
