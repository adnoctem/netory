package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/config"
	"github.com/adnoctem/netory/internal/pivot/server"
	"github.com/adnoctem/netory/pkg/log"
)

// runServer opens the application state and serves until signalled.
func runServer(parent context.Context, cfg config.Config) error {
	ctx, stop := signalContext(parent)
	defer stop()

	logger := log.New(
		log.WithLevel(cfg.LogLevel),
		log.WithFormat(cfg.LogFormat),
		log.WithAttrs(
			slog.String("service", app.Name),

			// Every line carries the replica, because on a multi-replica
			// deployment a log line without it answers half the question.
			slog.String("replica", cfg.Replica),
		),
	)

	state, err := app.Open(ctx, cfg, logger)
	if err != nil {
		return err
	}
	// closeState deliberately does not take ctx: see its documentation.
	//nolint:contextcheck // the close path must outlive the cancelled context
	defer closeState(state, logger, cfg.ShutdownGrace)

	state.LogStartup(ctx)

	srv, err := server.New(ctx, state)
	if err != nil {
		return err
	}

	logger.Info("admin socket ready", "path", srv.AdminSocket())

	if err := srv.Start(ctx); err != nil {
		if errors.Is(err, errShutdown) {
			return nil
		}

		return fmt.Errorf("server: %w", err)
	}

	logger.Info(app.Name + " stopped")

	return nil
}

// closeState shuts the application state down within a grace period.
//
// It builds its own context rather than taking one. By the time this runs the
// server's context has been cancelled by the signal that started the
// shutdown, and the close path still needs to release its outbox claims and
// finish a last delivery attempt - inheriting an expired context would cut all
// of that short at zero.
func closeState(state *app.State, logger *log.Logger, grace time.Duration) {
	if grace <= 0 {
		grace = time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()

	if err := state.Close(ctx); err != nil {
		logger.Error("could not close cleanly", "error", err)
	}
}
