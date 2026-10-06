// Package app is protean's application state: the wiring that turns a
// configuration and a secret into a running set of repositories, a provider
// registry and an event bus.
//
// # One binary, one database owner
//
// Only `protean server start` calls Open. Every other subcommand is a
// short-lived admin-socket client, because the server is the only process
// allowed to hold the Badger directory - and Badger's exclusive directory lock
// means a second process could not open it even if this code tried. The
// constraint is enforced at the filesystem level rather than merely documented.
//
// # Namespaces
//
// Each repository gets its own kv namespace, bound once into an immutable
// kv.Handle at startup. That is the ergonomic replacement for gopskit's
// SetNamespace: there is no current namespace to move, so no request can write
// into another's keyspace.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/adnoctem/netory/internal/protean/config"
	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
	"github.com/adnoctem/netory/pkg/log"
	"github.com/adnoctem/netory/pkg/notify"
	"github.com/adnoctem/netory/pkg/secret"
	"github.com/adnoctem/netory/pkg/stamp"
)

// Name is the application name, used in logs, the CLI and the socket path.
const Name = "protean"

// HKDF info labels. Each purpose gets its own, so a key compromised in one
// place reveals nothing about the others.
const (
	// InfoKVEncryption derives the Badger encryption key.
	InfoKVEncryption = "protean/kv-encryption"

	// InfoWebhookSigning derives the webhook HMAC key. pkg/notify owns the
	// actual derivation; this constant documents protean's half of the label
	// space.
	InfoWebhookSigning = "protean/webhook-signing"
)

// Namespaces in the key-value store. Separate namespaces rather than key
// prefixes within one, so a scan for hosts cannot see tokens.
const (
	NamespaceHosts     = "hosts"
	NamespaceTokens    = "tokens"
	NamespaceConfig    = "config"
	NamespaceSettings  = "settings"
	NamespaceOutbox    = "outbox"
	NamespaceRateLimit = "ratelimit"
)

// State is protean's running application state.
//
// The server holds one. CLI subcommands do not: they talk to the server over
// the admin socket and never construct this.
type State struct {
	Config config.Config
	Log    *log.Logger
	Stamp  *stamp.Stamps

	// Secret is the validated service secret. Every key in use is derived
	// from it; the raw value is not reachable through it.
	Secret *secret.Secret

	// Store is the encrypted Badger database.
	Store *badgerkv.Store

	// Repositories, each bound to its own namespace.
	Hosts     *Hosts
	Tokens    *Tokens
	Providers *Providers
	Notifiers *Notifiers
	Settings  *SettingsStore

	// RateLimit is the namespace handle the server's limiter counts in.
	RateLimit kv.Handle

	// Bus persists and delivers events.
	Bus    *event.Bus
	Outbox *event.Outbox
}

// Options are the dependencies New assembles a State from.
type Options struct {
	// Config is the bootstrap configuration.
	Config config.Config

	// Logger is where everything, including the audit trail, goes.
	Logger *log.Logger

	// Store is an already-open database. New does not open or close it; the
	// caller owns its lifetime, which is what lets `server start` enforce
	// being the only process that opens one.
	Store *badgerkv.Store

	// Secret is the validated service secret.
	Secret *secret.Secret

	// StartDelivery runs the event bus's delivery loop in the background.
	// Open sets it. A caller that wants to drive delivery itself - a test
	// asserting on the outbox, say - leaves it off and calls
	// Bus.DeliverDue directly, so nothing races it.
	StartDelivery bool

	// DedupWindow overrides the event deduplication window. Zero takes the
	// stored setting; negative disables deduplication.
	DedupWindow time.Duration
}

// New assembles the application state around an already-open store.
//
// The store and the secret are arguments rather than things New obtains for
// itself, which is what keeps `server start` the single place a database is
// opened: nothing else can reach this without first having opened one.
func New(ctx context.Context, opts Options) (*State, error) {
	if opts.Store == nil {
		return nil, errors.New("app: a store is required")
	}

	if opts.Logger == nil {
		return nil, errors.New("app: a logger is required")
	}

	if opts.Secret == nil {
		return nil, errors.New("app: a secret is required")
	}

	state := &State{
		Config: opts.Config,
		Log:    opts.Logger,
		Stamp:  stamp.New(),
		Secret: opts.Secret,
		Store:  opts.Store,
	}

	if err := state.bindNamespaces(); err != nil {
		return nil, err
	}

	if err := state.startBus(ctx, opts); err != nil {
		return nil, err
	}

	return state, nil
}

// Open reads the secret, opens the encrypted database and assembles the state.
//
// This is the only place the database is opened, and its only caller is
// `server start`.
func Open(ctx context.Context, cfg config.Config, logger *log.Logger) (*State, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	raw, err := config.ReadSecret()
	if err != nil {
		return nil, err
	}

	sec, err := secret.Parse(raw)
	if err != nil {
		return nil, err
	}

	// The Badger key is derived, never the secret itself: Badger accepts 16,
	// 24 or 32 bytes and would take a wrong-length slice of a raw secret
	// without complaint.
	encryptionKey, err := sec.DeriveEncryptionKey(InfoKVEncryption)
	if err != nil {
		return nil, err
	}

	store, err := badgerkv.New(badgerkv.Options{
		Path:          cfg.Database,
		EncryptionKey: encryptionKey,
		Logger:        logger,
	})
	if err != nil {
		return nil, err
	}

	state, err := New(ctx, Options{
		Config:        cfg,
		Logger:        logger,
		Store:         store,
		Secret:        sec,
		StartDelivery: true,
	})
	if err != nil {
		_ = store.Close()

		return nil, err
	}

	return state, nil
}

// bindNamespaces creates the per-namespace handles once, at startup.
//
// Binding here rather than per request means a malformed namespace fails at
// start - where there is one error path and nothing is serving yet - instead of
// on whichever request happens to touch it first.
func (s *State) bindNamespaces() error {
	hosts, err := kv.In(s.Store, NamespaceHosts)
	if err != nil {
		return fmt.Errorf("bind the %s namespace: %w", NamespaceHosts, err)
	}

	tokens, err := kv.In(s.Store, NamespaceTokens)
	if err != nil {
		return fmt.Errorf("bind the %s namespace: %w", NamespaceTokens, err)
	}

	instanceConfig, err := kv.In(s.Store, NamespaceConfig)
	if err != nil {
		return fmt.Errorf("bind the %s namespace: %w", NamespaceConfig, err)
	}

	settings, err := kv.In(s.Store, NamespaceSettings)
	if err != nil {
		return fmt.Errorf("bind the %s namespace: %w", NamespaceSettings, err)
	}

	outbox, err := kv.In(s.Store, NamespaceOutbox)
	if err != nil {
		return fmt.Errorf("bind the %s namespace: %w", NamespaceOutbox, err)
	}

	rateLimit, err := kv.In(s.Store, NamespaceRateLimit)
	if err != nil {
		return fmt.Errorf("bind the %s namespace: %w", NamespaceRateLimit, err)
	}

	s.Hosts = NewHosts(hosts)
	s.Tokens = NewTokens(tokens, s.Log)
	s.Providers = NewProviders(instanceConfig)
	s.Notifiers = NewNotifiers(instanceConfig)
	s.Settings = NewSettingsStore(settings)
	s.RateLimit = rateLimit
	s.Outbox = event.NewOutbox(outbox, s.Log)

	return nil
}

// startBus builds the event bus and subscribes every configured notifier.
func (s *State) startBus(ctx context.Context, opts Options) error {
	settings, err := s.Settings.Load(ctx)
	if err != nil {
		return err
	}

	window := opts.DedupWindow
	if window == 0 {
		window = settings.NotifyDedupWindow
	}

	bus, err := event.NewBus(event.BusOptions{
		Outbox:      s.Outbox,
		Logger:      s.Log,
		DedupWindow: window,
	})
	if err != nil {
		return err
	}

	s.Bus = bus

	if err := s.SubscribeNotifiers(ctx); err != nil {
		return err
	}

	if opts.StartDelivery {
		bus.Start(ctx, 0)
	}

	return nil
}

// SubscribeNotifiers builds and subscribes every configured notifier.
//
// A notifier that fails to build is logged and skipped rather than failing
// startup. The alternative - refusing to start - means one stale notifier
// configuration takes the whole dynDNS service down, which trades a
// notification outage for a DNS outage.
func (s *State) SubscribeNotifiers(ctx context.Context) error {
	configs, err := s.Notifiers.List(ctx)
	if err != nil {
		return err
	}

	for _, cfg := range configs {
		notifier, err := notify.New(cfg, s.Secret)
		if err != nil {
			s.Log.Error("skipping a notifier that could not be configured",
				"notifier", cfg.Name, "kind", cfg.Kind, "error", err)

			continue
		}

		s.Bus.Subscribe(notifier)
		s.Log.Info("notifier subscribed", "notifier", cfg.Name, "kind", cfg.Kind)
	}

	return nil
}

// LoadSettings returns the current runtime settings.
func (s *State) LoadSettings(ctx context.Context) (Settings, error) {
	return s.Settings.Load(ctx)
}

// ApplySettings stores settings and applies the ones that take effect
// immediately.
func (s *State) ApplySettings(ctx context.Context, settings Settings) error {
	if err := s.Settings.Save(ctx, settings); err != nil {
		return err
	}

	// The log level is the one setting that must take effect without a
	// restart, because the reason to change it is usually that something is
	// going wrong right now.
	if settings.LogLevel != "" {
		if level, ok := log.ParseLevel(settings.LogLevel); ok {
			s.Log.SetLevel(level)
		}
	}

	return nil
}

// Publish persists an event for delivery, logging rather than returning a
// failure.
//
// Callers are request handlers whose own work has already succeeded: an update
// written to the provider must not be reported as failed because the
// notification could not be queued. The log is where that is recorded.
func (s *State) Publish(ctx context.Context, e event.Event) {
	if s.Bus == nil {
		return
	}

	if err := s.Bus.Publish(ctx, e); err != nil {
		s.Log.Error("could not queue an event for delivery",
			"type", e.Type, "subject", e.Subject, "error", err)
	}
}

// Close stops the bus and closes the database.
func (s *State) Close(ctx context.Context) error {
	var errs []error

	if s.Bus != nil {
		stopCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if err := s.Bus.Stop(stopCtx); err != nil {
			errs = append(errs, err)
		}
	}

	// The database is closed last: the bus writes to the outbox, so closing
	// the store first would make a final delivery attempt fail on a closed
	// store rather than complete.
	if s.Store != nil {
		if err := s.Store.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close the database: %w", err))
		}
	}

	return errors.Join(errs...)
}

// LogStartup records what the server is about to do, at info, so an operator
// reading the first lines of the log can see the configuration in effect.
//
// The TLS mode and the trusted-proxy list are the two values worth seeing
// immediately: together they determine whether protean can tell where a request
// came from, and getting them wrong is silent.
func (s *State) LogStartup() {
	attrs := []any{
		slog.String("version", s.Stamp.Version),
		slog.String("commit", s.Stamp.CommitSHA),
	}

	for key, value := range s.Config.Redacted() {
		attrs = append(attrs, slog.String(key, value))
	}

	s.Log.Info(Name+" starting", attrs...)

	if s.Config.ProxyMode() && len(s.Config.TrustedProxies) == 0 {
		s.Log.Warn(
			"serving plain HTTP with no trusted proxies configured: " +
				"X-Forwarded-For will be ignored, so every client will appear to come from the proxy's address")
	}
}
