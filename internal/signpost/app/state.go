// Package app is signpost's application state: the wiring that turns a
// configuration and a secret into a running set of repositories, a content
// store and an event bus, plus the orchestration behind publishing.
//
// # One binary, one database owner
//
// Only `signpost server start` calls Open. Every other subcommand is a
// short-lived admin-socket client, because the server is the only process
// allowed to hold the Badger directory - and Badger's exclusive directory lock
// means a second process could not open it even if this code tried.
//
// # Where the integrity guarantee lives
//
// signpost sells one property: the bytes it serves are the bytes that were
// published. Three things in this package hold it up. A release is created
// with SetIfAbsent, so a release name can never come to mean two different
// sets of bytes. Content is stored under its own digest and verified on read,
// so a file altered on disk is detected rather than served. And the route
// table is swapped whole through an atomic.Pointer, so no request can observe
// a half-published state.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/adnoctem/netory/internal/signpost/config"
	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
	"github.com/adnoctem/netory/pkg/log"
	"github.com/adnoctem/netory/pkg/notify"
	"github.com/adnoctem/netory/pkg/secret"
	"github.com/adnoctem/netory/pkg/stamp"
)

// Name is the application name, used in logs, the CLI and the socket path.
const Name = "signpost"

// HKDF info labels, one per purpose, so a key compromised in one place
// reveals nothing about the others.
const (
	// InfoKVEncryption derives the Badger encryption key.
	InfoKVEncryption = "signpost/kv-encryption"

	// InfoWebhookSigning derives the webhook HMAC key. pkg/notify owns the
	// derivation; this constant documents signpost's half of the label space.
	InfoWebhookSigning = "signpost/webhook-signing"
)

// Namespaces in the key-value store. Separate namespaces rather than key
// prefixes within one, so a scan for releases cannot see notifier
// credentials.
const (
	NamespaceReleases = "releases"
	NamespaceAliases  = "aliases"
	NamespaceConfig   = "config"
	NamespaceSettings = "settings"
	NamespaceOutbox   = "outbox"
)

// State is signpost's running application state.
type State struct {
	Config config.Config
	Log    *log.Logger
	Stamp  *stamp.Stamps

	// Secret is the validated service secret. Every key in use is derived
	// from it; the raw value is not reachable through it.
	Secret *secret.Secret

	// Store is the encrypted Badger database.
	Store *badgerkv.Store

	// Content holds the served bytes (§5.1).
	Content Storage

	// Repositories, each bound to its own namespace.
	Releases  *Releases
	Aliases   *Aliases
	Notifiers *Notifiers
	Settings  *SettingsStore

	// Bus persists and delivers events.
	Bus    *event.Bus
	Outbox *event.Outbox

	// table is the atomically swapped serving snapshot. Only RebuildTable
	// stores into it and only Table loads from it.
	table routeTablePointer

	// cache holds served content in memory, keyed by digest.
	cache *contentCache

	// publishMu serialises publishes, rollbacks and removals.
	//
	// Not what makes them safe - SetIfAbsent and CompareAndSwap do that, and
	// they hold across processes where a mutex would not. This only keeps one
	// server's own concurrent admin requests from doing redundant work and
	// from interleaving their route-table rebuilds, so the last rebuild is
	// always the one that reflects the last write.
	publishMu chan struct{}
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

	// Content is the content store. New creates a local one under
	// Config.Content when this is nil, which is what a test overrides.
	Content Storage

	// Secret is the validated service secret.
	Secret *secret.Secret

	// StartDelivery runs the event bus's delivery loop in the background.
	// Open sets it; a test that wants to drive delivery itself leaves it off
	// and calls Bus.DeliverDue directly.
	StartDelivery bool

	// DedupWindow overrides the event deduplication window. Zero takes the
	// stored setting; negative disables deduplication.
	DedupWindow time.Duration

	// CacheBytes overrides the content cache budget. Zero takes
	// DefaultCacheBytes; negative disables caching.
	CacheBytes int64
}

// New assembles the application state around an already-open store.
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

	content := opts.Content
	if content == nil {
		local, err := NewLocalStorage(opts.Config.Content)
		if err != nil {
			return nil, err
		}

		content = local
	}

	budget := opts.CacheBytes
	if budget == 0 {
		budget = DefaultCacheBytes
	}

	state := &State{
		Config:    opts.Config,
		Log:       opts.Logger,
		Stamp:     stamp.New(),
		Secret:    opts.Secret,
		Store:     opts.Store,
		Content:   content,
		cache:     newContentCache(budget),
		publishMu: make(chan struct{}, 1),
	}

	if err := state.bindNamespaces(); err != nil {
		return nil, err
	}

	if err := state.startBus(ctx, opts); err != nil {
		return nil, err
	}

	// Built before anything can serve, so the first request reads a table
	// rather than finding none.
	if err := state.RebuildTable(ctx); err != nil {
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

// bindNamespaces creates the per-namespace handles once, at startup, so a
// malformed namespace fails at start rather than on whichever request happens
// to touch it first.
func (s *State) bindNamespaces() error {
	releases, err := kv.In(s.Store, NamespaceReleases)
	if err != nil {
		return fmt.Errorf("bind the %s namespace: %w", NamespaceReleases, err)
	}

	aliases, err := kv.In(s.Store, NamespaceAliases)
	if err != nil {
		return fmt.Errorf("bind the %s namespace: %w", NamespaceAliases, err)
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

	s.Releases = NewReleases(releases)
	s.Aliases = NewAliases(aliases)
	s.Notifiers = NewNotifiers(instanceConfig)
	s.Settings = NewSettingsStore(settings)
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

	// Deduplication is off unless an operator asks for it, which is the
	// opposite of protean's default and deliberately so.
	//
	// pkg/event collapses events on type and subject, which is right for a
	// dynDNS host flapping between two addresses: nobody wants a mail per
	// flap. Every signpost event is a human administrative act arriving over
	// a local socket, so there is nothing to flap - and the one sequence that
	// would be collapsed is the one that matters most. Publish a bad release,
	// notice, roll back: three alias.changed events for the same alias,
	// comfortably inside a one-minute window, of which an operator would hear
	// only the first. Losing the rollback notification is exactly the
	// notification not to lose.
	if window == 0 {
		window = -1
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
// startup: one stale notifier configuration must not stop signpost serving
// scripts, because the scripts are the service and the notification is not.
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

	// serve.alias and serve.versioned decide what the public listener serves,
	// and the serving path reads them from the route table rather than from
	// settings. Rebuilding unconditionally rather than comparing which
	// setting changed: the rebuild is cheap, happens on an admin request, and
	// comparing would be one more place to forget a field.
	return s.RebuildTable(ctx)
}

// ServeContent returns the bytes for a resolved route.
//
// The cache is consulted first and populated from storage, which is where
// digest verification happens. A route resolved from the table but missing
// from storage is an error rather than a 404: the table was built from the
// database, so the metadata and the content have diverged, and that is a fault
// to report rather than an absence to shrug at.
func (s *State) ServeContent(ctx context.Context, res Resolution) ([]byte, error) {
	if content, ok := s.cache.get(res.Route.SHA256); ok {
		return content, nil
	}

	content, err := s.Content.Get(ctx, res.Release, res.Route.SHA256)
	if err != nil {
		return nil, err
	}

	s.cache.put(res.Route.SHA256, content)

	return content, nil
}

// CacheStats reports the content cache's occupancy for the admin API.
func (s *State) CacheStats() (entries int, bytes, budget int64) { return s.cache.stats() }

// Publish persists an event for delivery, logging rather than returning a
// failure: a publish that succeeded must not be reported as failed because the
// notification could not be queued.
func (s *State) Publish(ctx context.Context, e event.Event) {
	if s.Bus == nil {
		return
	}

	if err := s.Bus.Publish(ctx, e); err != nil {
		s.Log.Error("could not queue an event for delivery",
			"type", e.Type, "subject", e.Subject, "error", err)
	}
}

// lock serialises a publish-path operation, respecting ctx.
func (s *State) lock(ctx context.Context) error {
	select {
	case s.publishMu <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// unlock releases the publish-path lock.
func (s *State) unlock() {
	select {
	case <-s.publishMu:
	default:
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
func (s *State) LogStartup(ctx context.Context) {
	attrs := []any{
		slog.String("version", s.Stamp.Version),
		slog.String("commit", s.Stamp.CommitSHA),
		slog.String("content.store", s.Content.Describe()),
	}

	for key, value := range s.Config.Redacted() {
		attrs = append(attrs, slog.String(key, value))
	}

	s.Log.Info(Name+" starting", attrs...)

	table := s.Table()
	s.Log.Info("serving",
		"alias", table.Alias,
		"release", table.Release,
		"routes", table.Len(),
		"releases", len(table.Releases()))

	// The one configuration mistake that silently breaks the guarantee in
	// §6.2: plain HTTP with no trusted proxies means signpost cannot confirm
	// any request arrived over TLS, so it will refuse to serve every script.
	// Said at warn at startup rather than discovered as a wall of 421s.
	if s.Config.ProxyMode() && len(s.Config.TrustedProxies) == 0 {
		s.Log.Warn(
			"serving plain HTTP with no trusted proxies configured: " +
				"signpost cannot confirm a request arrived over HTTPS and will refuse to serve scripts. " +
				"Set SIGNPOST_TRUSTED_PROXIES, or configure a certificate and key")
	}

	if settings, err := s.LoadSettings(ctx); err == nil && settings.AccessLogAddress == AccessLogFull {
		s.Log.Warn(
			"the access log is recording full client addresses: " +
				"this is personal data, so make sure the retention of your log pipeline accounts for it")
	}
}
