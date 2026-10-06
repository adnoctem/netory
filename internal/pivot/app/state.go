// Package app is pivot's application state: the wiring that turns a
// configuration and a secret into a running set of Valkey-backed repositories,
// a compiled rule table, a rate limiter and an event bus.
//
// # Stateless replicas, shared state
//
// This is where pivot differs structurally from protean and signpost. They are
// single-process services whose server owns an exclusive Badger directory;
// pivot is several replicas behind a load balancer, holding nothing between
// requests that cannot be lost. Every piece of shared state is in Valkey, so
// there is no consensus to run and no replica that is special.
//
// Three consequences run through this package. A change made through one
// replica's admin socket has to reach the others, which is what the rule
// version counter and its pub/sub announcement are for (§10.3). Notifications
// must not be sent once per replica, which is what the outbox claim is for
// (§10.4). And every value that would have been protected by Badger's
// encryption at rest has to be sealed by pivot before it is written, because
// Valkey has none (§8).
//
// # Every replica needs the same secret
//
// Keys derived from PIVOT_SECRET decrypt the backend credentials and notifier
// configuration in Valkey. A replica given a different secret starts cleanly,
// serves the token endpoint, and then fails every forward leg - so the failure
// appears as a backend problem rather than as the configuration mistake it is.
// The errors from Clients and Notifiers say so explicitly for that reason.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/internal/pivot/cache"
	"github.com/adnoctem/netory/internal/pivot/config"
	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/valkeykv"
	"github.com/adnoctem/netory/pkg/log"
	"github.com/adnoctem/netory/pkg/notify"
	"github.com/adnoctem/netory/pkg/seal"
	"github.com/adnoctem/netory/pkg/secret"
	"github.com/adnoctem/netory/pkg/stamp"
)

// Name is the application name, used in logs, the CLI and the socket path.
const Name = "pivot"

// HKDF info labels, one per purpose, as §8.1 names them.
const (
	// InfoCredentialEncryption derives the key that seals backend credentials
	// and notifier configuration.
	InfoCredentialEncryption = "pivot/credential-encryption"

	// InfoCacheEncryption derives the key that seals cached responses on
	// routes marked encrypt (§7.3).
	InfoCacheEncryption = cache.InfoCacheEncryption

	// InfoWebhookSigning derives the webhook HMAC key. pkg/notify owns the
	// derivation; this documents pivot's half of the label space.
	InfoWebhookSigning = "pivot/webhook-signing"
)

// CredentialMagic identifies a sealed pivot credential.
const CredentialMagic = "NTRYPV"

// Namespaces in Valkey. Separate namespaces rather than key prefixes within
// one, so a scan for clients cannot see tokens.
const (
	NamespaceClients   = "clients"
	NamespaceTokens    = "tokens"
	NamespaceConfig    = "config"
	NamespaceSettings  = "settings"
	NamespaceOutbox    = "outbox"
	NamespaceRateLimit = "ratelimit"
	NamespaceCache     = "cache"
	NamespaceAudit     = "audit"
)

// State is pivot's running application state.
type State struct {
	Config config.Config
	Log    *log.Logger
	Stamp  *stamp.Stamps

	// Secret is the validated service secret. Every key in use is derived
	// from it; the raw value is not reachable through it.
	Secret *secret.Secret

	// Store is the Valkey connection.
	Store *valkeykv.Store

	// Repositories, each bound to its own namespace.
	Clients   *Clients
	Tokens    *Tokens
	Notifiers *Notifiers
	Settings  *SettingsStore
	Rules     *RuleStore

	// Reloader keeps this replica's compiled rule table in step with Valkey.
	Reloader *Reloader

	// Limiter applies per-client token buckets, shared across replicas.
	Limiter *Limiter

	// Cache holds cacheable responses.
	Cache *cache.Store

	// Audit is the trail pivot stores itself.
	Audit *Audit

	// Bus persists and delivers events, claiming entries so one replica sends
	// each notification.
	Bus    *event.Bus
	Outbox *event.Outbox

	// backends caches built backend authenticators per client, so the oauth2
	// token manager's in-process state survives between requests. Without it
	// every request would build a fresh authenticator with no token and go
	// back to the backend's token endpoint.
	backends *backendCache

	// settings is the last loaded settings document, refreshed on each admin
	// change and read by the request path.
	settings *settingsCache

	// sealer seals credentials. Held so the token cache can reach it without
	// re-deriving the key per call.
	sealer *seal.Sealer
}

// credentialSealer returns the sealer for credentials.
func (s *State) credentialSealer() *seal.Sealer { return s.sealer }

// CachedBackends reports how many backend authenticators this replica holds,
// for `config view`.
func (s *State) CachedBackends() int { return s.backends.len() }

// Options are the dependencies New assembles a State from.
type Options struct {
	// Config is the bootstrap configuration.
	Config config.Config

	// Logger is where everything, including the audit trail, goes.
	Logger *log.Logger

	// Store is an already-open Valkey connection. New does not close it.
	Store *valkeykv.Store

	// Secret is the validated service secret.
	Secret *secret.Secret

	// StartBackground runs the event delivery loop and the rule reloader.
	// Open sets it; a test that drives them itself leaves it off.
	StartBackground bool

	// HTTPClient is used for backend token requests. Nil means a client with
	// the configured backend timeout.
	HTTPClient *http.Client

	// ReloadPoll overrides the rule reload cadence.
	ReloadPoll time.Duration

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// New assembles the application state around an already-open Valkey
// connection.
func New(ctx context.Context, opts Options) (*State, error) {
	if opts.Store == nil {
		return nil, errors.New("app: a Valkey store is required")
	}

	if opts.Logger == nil {
		return nil, errors.New("app: a logger is required")
	}

	if opts.Secret == nil {
		return nil, errors.New("app: a secret is required")
	}

	credentialKey, err := opts.Secret.DeriveEncryptionKey(InfoCredentialEncryption)
	if err != nil {
		return nil, err
	}

	credentialSealer, err := seal.New(CredentialMagic, credentialKey)
	if err != nil {
		return nil, err
	}

	cacheKey, err := opts.Secret.DeriveEncryptionKey(InfoCacheEncryption)
	if err != nil {
		return nil, err
	}

	state := &State{
		sealer:   credentialSealer,
		Config:   opts.Config,
		Log:      opts.Logger,
		Stamp:    stamp.New(),
		Secret:   opts.Secret,
		Store:    opts.Store,
		settings: newSettingsCache(),
	}

	if err := state.bind(ctx, opts, credentialSealer, cacheKey); err != nil {
		return nil, err
	}

	if err := state.startBus(ctx, opts); err != nil {
		return nil, err
	}

	if opts.StartBackground {
		state.Reloader.Start(ctx)
	}

	return state, nil
}

// Open reads the secret, connects to Valkey and assembles the state.
//
// Unlike protean's and signpost's Open, this one may be called by several
// processes at once: that is the point of pivot. There is no exclusive lock to
// take and nothing to coordinate.
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

	store, err := valkeykv.New(valkeykv.Options{
		Address:    cfg.Valkey.Address,
		Username:   cfg.Valkey.Username,
		Password:   cfg.Valkey.Password,
		DB:         cfg.Valkey.DB,
		TLSConfig:  cfg.Valkey.TLSConfig(),
		ClientName: Name + "/" + cfg.Replica,
	})
	if err != nil {
		return nil, err
	}

	// Checked before anything else is wired: a pivot that cannot reach Valkey
	// has no state at all, and failing here says so plainly rather than
	// letting the first request discover it.
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := store.Ping(pingCtx); err != nil {
		_ = store.Close()

		return nil, fmt.Errorf("app: Valkey is not reachable: %w", err)
	}

	state, err := New(ctx, Options{
		Config:          cfg,
		Logger:          logger,
		Store:           store,
		Secret:          sec,
		StartBackground: true,
	})
	if err != nil {
		_ = store.Close()

		return nil, err
	}

	return state, nil
}

// bind creates the namespace handles and the repositories over them.
func (s *State) bind(
	ctx context.Context, opts Options, credentials *seal.Sealer, cacheKey []byte,
) error {
	handles := map[string]kv.Handle{}

	for _, namespace := range []string{
		NamespaceClients, NamespaceTokens, NamespaceConfig, NamespaceSettings,
		NamespaceOutbox, NamespaceCache, NamespaceAudit,
	} {
		handle, err := kv.In(s.Store, namespace)
		if err != nil {
			return fmt.Errorf("app: bind the %s namespace: %w", namespace, err)
		}

		handles[namespace] = handle
	}

	s.Clients = NewClients(handles[NamespaceClients], credentials)
	s.Tokens = NewTokens(handles[NamespaceTokens], opts.Now)
	s.Notifiers = NewNotifiers(handles[NamespaceConfig], credentials)
	s.Settings = NewSettingsStore(handles[NamespaceSettings])
	s.Rules = NewRuleStore(handles[NamespaceConfig])
	s.Outbox = event.NewOutbox(handles[NamespaceOutbox], s.Log)

	limiter, err := NewLimiter(s.Store, NamespaceRateLimit, opts.Now)
	if err != nil {
		return err
	}

	s.Limiter = limiter

	codec, err := cache.NewCodec(cacheKey)
	if err != nil {
		return err
	}

	cacheStore, err := cache.NewStore(cache.StoreOptions{
		Handle: handles[NamespaceCache],
		Codec:  codec,
		Logger: s.Log,
		Now:    opts.Now,
	})
	if err != nil {
		return err
	}

	s.Cache = cacheStore

	// Loaded once here so the audit trail's retention source and the request
	// path both have something to read before the first admin call.
	settings, err := s.Settings.Load(ctx)
	if err != nil {
		return err
	}

	s.settings.store(settings)

	audit, err := NewAudit(AuditOptions{
		Store:     handles[NamespaceAudit],
		Logger:    s.Log,
		Replica:   s.Config.Replica,
		Retention: func() time.Duration { return s.settings.load().AuditRetention },
		Now:       opts.Now,
	})
	if err != nil {
		return err
	}

	s.Audit = audit

	reloader, err := NewReloader(ctx, ReloaderOptions{
		Rules:   s.Rules,
		Clients: s.Clients,
		Store:   s.Store,
		Logger:  s.Log,
		Poll:    opts.ReloadPoll,
	})
	if err != nil {
		return err
	}

	s.Reloader = reloader

	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: s.Config.BackendTimeout}
	}

	s.backends = newBackendCache(s, httpClient, opts.Now)

	return nil
}

// startBus builds the event bus and subscribes every configured notifier.
//
// The bus is given this replica's identity as its claim holder, which is what
// makes one replica send each notification rather than all of them (§10.4).
func (s *State) startBus(ctx context.Context, opts Options) error {
	settings := s.settings.load()

	window := settings.NotifyDedupWindow
	if window == 0 {
		// Zero means every event is delivered. pivot's events are already
		// aggregated at the source - §8.3's rule.denied and
		// client.rate_limited carry counts - so collapsing on top of that
		// would hide the second distinct incident of a minute.
		window = -1
	}

	bus, err := event.NewBus(event.BusOptions{
		Outbox:      s.Outbox,
		Logger:      s.Log,
		DedupWindow: window,
		Holder:      s.Config.Replica,
	})
	if err != nil {
		return err
	}

	s.Bus = bus

	if err := s.SubscribeNotifiers(ctx); err != nil {
		return err
	}

	if opts.StartBackground {
		bus.Start(ctx, 0)
	}

	return nil
}

// SubscribeNotifiers builds and subscribes every configured notifier.
//
// A notifier that fails to build is logged and skipped rather than failing
// startup: a stale notifier configuration must not stop pivot proxying, since
// the proxying is the service and the notification is not.
func (s *State) SubscribeNotifiers(ctx context.Context) error {
	configs, err := s.Notifiers.List(ctx)
	if err != nil {
		// A replica that cannot decrypt its notifier configuration still
		// serves traffic. It says which notifiers exist, so the operator can
		// see the secret is wrong rather than concluding none are configured.
		names, nameErr := s.Notifiers.Names(ctx)
		if nameErr == nil && len(names) > 0 {
			s.Log.Error("could not read the notifier configuration; no notifications will be sent",
				"notifiers", len(names), "error", err)

			return nil
		}

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

// LoadSettings returns the current runtime settings, from the cached copy.
//
// Cached because the request path reads them per request and a Valkey round
// trip per request to fetch a document that changes rarely would be a
// self-inflicted cost. The cache is refreshed by ApplySettings on this replica
// and by the rule reloader on the others, which is why a settings change bumps
// the rule version.
func (s *State) LoadSettings(_ context.Context) (Settings, error) {
	return s.settings.load(), nil
}

// RefreshSettings re-reads the settings document from Valkey.
func (s *State) RefreshSettings(ctx context.Context) error {
	settings, err := s.Settings.Load(ctx)
	if err != nil {
		return err
	}

	s.settings.store(settings)

	return nil
}

// ApplySettings stores settings, applies what takes effect at once, and tells
// the other replicas.
func (s *State) ApplySettings(ctx context.Context, settings Settings) error {
	if err := s.Settings.Save(ctx, settings); err != nil {
		return err
	}

	s.settings.store(settings)

	// The log level is the one setting that must take effect without a
	// restart, because the reason to change it is usually that something is
	// going wrong right now.
	if settings.LogLevel != "" {
		if level, ok := log.ParseLevel(settings.LogLevel); ok {
			s.Log.SetLevel(level)
		}
	}

	// A settings change is a rule-version change as far as the other replicas
	// are concerned: they cache settings too, and the version counter is the
	// one signal that tells them to re-read. One counter for everything is
	// cheaper than one per thing and a replica only needs to know that
	// something moved.
	return s.Invalidate(ctx)
}

// Invalidate bumps the rule version and announces it, so every replica
// rebuilds.
//
// Called after any administrative change: rules, clients, settings. The bump
// is what guarantees convergence and the announcement is what makes it fast.
func (s *State) Invalidate(ctx context.Context) error {
	version, err := s.Rules.Bump(ctx)
	if err != nil {
		return err
	}

	// This replica reloads immediately rather than waiting for its own
	// announcement, so an operator who changes a rule and then tests it
	// through this same replica sees the new behaviour.
	if err := s.Reloader.Reload(ctx); err != nil {
		return err
	}

	if err := s.RefreshSettings(ctx); err != nil {
		return err
	}

	s.Reloader.Announce(ctx, version)

	return nil
}

// Backend returns the backend authenticator for a client.
func (s *State) Backend(client Client) (auth.Backend, error) {
	return s.backends.get(client)
}

// ForgetBackend drops a client's cached authenticator, so the next request
// builds a fresh one.
//
// Called when a client's credentials change. Without it, a replica would keep
// using the backend token it fetched with the old credentials until that token
// expired - which looks like a rotation that did not take effect.
func (s *State) ForgetBackend(client string) { s.backends.forget(client) }

// Publish persists an event for delivery, logging rather than returning a
// failure: a request that succeeded must not be reported as failed because a
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

// Close stops the background loops and closes the Valkey connection.
func (s *State) Close(ctx context.Context) error {
	var errs []error

	if s.Reloader != nil {
		s.Reloader.Stop()
	}

	if s.Bus != nil {
		stopCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		if err := s.Bus.Stop(stopCtx); err != nil {
			errs = append(errs, err)
		}
	}

	// Valkey last: the bus writes to the outbox on its way out, and closing
	// the connection first would make that final write fail rather than
	// complete.
	if s.Store != nil {
		if err := s.Store.Close(); err != nil {
			errs = append(errs, fmt.Errorf("app: close the Valkey connection: %w", err))
		}
	}

	return errors.Join(errs...)
}

// LogStartup records what this replica is about to do, so an operator reading
// the first lines of the log can see the configuration in effect.
func (s *State) LogStartup(ctx context.Context) {
	attrs := []any{
		slog.String("version", s.Stamp.Version),
		slog.String("commit", s.Stamp.CommitSHA),
	}

	for key, value := range s.Config.Redacted() {
		attrs = append(attrs, slog.String(key, value))
	}

	s.Log.Info(Name+" starting", attrs...)

	settings, err := s.LoadSettings(ctx)
	if err != nil {
		s.Log.Error("could not read settings", "error", err)

		return
	}

	table := s.Reloader.Table()
	deny, allow, routes := table.Global.Counts()

	s.Log.Info("rule table",
		"version", table.Version,
		"deny", deny,
		"allow", allow,
		"cacheable_routes", routes,
		"clients_with_rules", table.Clients())

	// An instance with no allow rules answers 403 to everything, which looks
	// like a broken service rather than an unconfigured one. Said at warn
	// because it is the state a fresh pivot starts in.
	if table.Global.Empty() {
		s.Log.Warn(
			"no allow rules are configured, so every request will be denied: " +
				"apply a rule set with `pivot rules apply <file>`; example " +
				"documents are in docs/examples/pivot/")
	}

	if settings.BackendURL == "" {
		s.Log.Warn("no backend URL is configured, so nothing can be forwarded: " +
			"set one with `pivot config set backend.url https://…`")
	}

	// §7.1's multiplication, stated rather than left in a document: scaling
	// out raises the load the backend can see unless this is lowered to match.
	if settings.BackendConcurrency > 0 {
		s.Log.Info("backend concurrency limit is per replica",
			"per_replica", settings.BackendConcurrency,
			"note", "the effective ceiling is this value multiplied by the replica count")
	}

	// The one configuration mistake that silently weakens §10.7: in proxy
	// mode with no trusted set, the client address pivot records and rate
	// limits on is the proxy's.
	if s.Config.ProxyMode() && len(s.Config.TrustedProxies) == 0 {
		s.Log.Warn(
			"serving plain HTTP with no trusted proxies configured: " +
				"X-Forwarded-For will be ignored, so every client will appear to come from the " +
				"proxy's address and the audit log will say so")
	}

	if settings.AccessLogAddress == AccessLogFull {
		s.Log.Warn(
			"the access log is recording full client addresses: this is personal data, " +
				"so make sure your log pipeline's retention accounts for it")
	}
}
