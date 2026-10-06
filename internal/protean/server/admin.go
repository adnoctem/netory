package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/internal/protean/provider"
	"github.com/adnoctem/netory/pkg/admin"
	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/notify"
)

// APIPrefix versions the admin API.
//
// The CLI and the server ship in the same binary, so they normally match - but
// an operator can have an older binary in PATH than the one running as the
// server, and a prefix makes a future incompatible change a new prefix rather
// than a silently misinterpreted request.
const APIPrefix = "/v1"

// adminHandler builds the admin routes.
//
// Every route is a thin translation between the CLI's intent and the
// repositories; no business logic lives here that the app package does not
// already own. That keeps the socket surface auditable: the interesting
// question about an admin API is what it exposes, and this file is the answer
// in full.
func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+APIPrefix+"/meta", s.adminMeta)

	mux.HandleFunc("GET "+APIPrefix+"/hosts", s.adminHostList)
	mux.HandleFunc("POST "+APIPrefix+"/hosts", s.adminHostAdd)
	mux.HandleFunc("GET "+APIPrefix+"/hosts/{name}", s.adminHostGet)
	mux.HandleFunc("DELETE "+APIPrefix+"/hosts/{name}", s.adminHostRemove)

	mux.HandleFunc("GET "+APIPrefix+"/tokens", s.adminTokenList)
	mux.HandleFunc("POST "+APIPrefix+"/tokens", s.adminTokenCreate)
	mux.HandleFunc("DELETE "+APIPrefix+"/tokens/{id}", s.adminTokenRevoke)
	mux.HandleFunc("POST "+APIPrefix+"/tokens/{id}/rotate", s.adminTokenRotate)

	mux.HandleFunc("GET "+APIPrefix+"/providers", s.adminProviderList)
	mux.HandleFunc("POST "+APIPrefix+"/providers", s.adminProviderAdd)
	mux.HandleFunc("DELETE "+APIPrefix+"/providers/{name}", s.adminProviderRemove)
	mux.HandleFunc("POST "+APIPrefix+"/providers/{name}/test", s.adminProviderTest)

	mux.HandleFunc("GET "+APIPrefix+"/notifiers", s.adminNotifierList)
	mux.HandleFunc("POST "+APIPrefix+"/notifiers", s.adminNotifierAdd)
	mux.HandleFunc("DELETE "+APIPrefix+"/notifiers/{name}", s.adminNotifierRemove)
	mux.HandleFunc("POST "+APIPrefix+"/notifiers/{name}/test", s.adminNotifierTest)

	// A distinct path rather than /config/view, which Go's mux would otherwise
	// have to disambiguate against /config/{name}.
	mux.HandleFunc("GET "+APIPrefix+"/configuration", s.adminConfigurationView)

	mux.HandleFunc("GET "+APIPrefix+"/config", s.adminConfigList)
	mux.HandleFunc("GET "+APIPrefix+"/config/{name}", s.adminConfigGet)
	mux.HandleFunc("PUT "+APIPrefix+"/config/{name}", s.adminConfigSet)

	mux.HandleFunc("GET "+APIPrefix+"/outbox", s.adminOutboxList)

	// Backups are taken by the server, not by the CLI: the server is the
	// process holding an instance or task role, and a plaintext snapshot of
	// every credential in the database has no business crossing a socket when
	// it does not have to. Restore is deliberately absent - it is an offline
	// command, because Badger's load merges rather than replaces and the
	// database must not be open.
	mux.HandleFunc("POST "+APIPrefix+"/backups", s.adminBackupCreate)
	mux.HandleFunc("GET "+APIPrefix+"/backups", s.adminBackupList)
	mux.HandleFunc("POST "+APIPrefix+"/backups/verify", s.adminBackupVerify)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		admin.WriteError(w, admin.Errorf(http.StatusNotFound, "no such admin endpoint: %s %s",
			r.Method, r.URL.Path).
			WithHint("this usually means the CLI is a different version from the running server"))
	})

	return mux
}

// MetaResponse is what `protean version` reports about the running server.
type MetaResponse struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	CommitSHA string `json:"commit_sha"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`

	// Providers and Notifiers are the compiled-in kinds, so `version` can tell
	// an operator what this binary supports without a separate call.
	Providers []string `json:"providers"`
	Notifiers []string `json:"notifiers"`
}

func (s *Server) adminMeta(w http.ResponseWriter, _ *http.Request) {
	stamps := s.state.Stamp

	admin.WriteJSON(w, http.StatusOK, MetaResponse{
		Name:      app.Name,
		Version:   stamps.Version,
		CommitSHA: stamps.CommitSHA,
		BuildDate: stamps.BuildDate,
		GoVersion: stamps.GoVersion,
		Platform:  stamps.Platform,
		Providers: provider.Kinds(),
		Notifiers: notify.Kinds(),
	})
}

// HostRequest is the body of `host add`.
type HostRequest struct {
	Name       string `json:"name"`
	Provider   string `json:"provider"`
	ManageA    *bool  `json:"manage_a,omitempty"`
	ManageAAAA *bool  `json:"manage_aaaa,omitempty"`
	TTL        string `json:"ttl,omitempty"`
}

func (s *Server) adminHostList(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.state.Hosts.List(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	// An empty slice rather than null, so the CLI can range over it without a
	// nil check and JSON consumers see [].
	if hosts == nil {
		hosts = []app.Host{}
	}

	admin.WriteJSON(w, http.StatusOK, hosts)
}

func (s *Server) adminHostGet(w http.ResponseWriter, r *http.Request) {
	host, err := s.state.Hosts.Get(r.Context(), r.PathValue("name"))
	if err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	admin.WriteJSON(w, http.StatusOK, host)
}

func (s *Server) adminHostAdd(w http.ResponseWriter, r *http.Request) {
	var req HostRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	// Both families default to on. A host configured for neither would accept
	// updates and write nothing, and IPv6 matters especially on DS-Lite.
	manageA, manageAAAA := true, true
	if req.ManageA != nil {
		manageA = *req.ManageA
	}
	if req.ManageAAAA != nil {
		manageAAAA = *req.ManageAAAA
	}

	var ttl time.Duration
	if req.TTL != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err != nil || parsed < 0 {
			admin.WriteError(w, admin.Errorf(http.StatusBadRequest,
				"ttl %q is not a duration", req.TTL).WithHint("use a value such as 60s or 5m"))

			return
		}

		ttl = parsed
	}

	ctx := r.Context()

	// The provider must exist, or the host would accept updates and fail to
	// write them - which presents as a DNS outage rather than a configuration
	// error.
	cfg, err := s.state.Providers.Get(ctx, req.Provider)
	if err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	host := app.Host{
		Name:       req.Name,
		Provider:   req.Provider,
		ManageA:    manageA,
		ManageAAAA: manageAAAA,
		TTL:        ttl,
	}

	// And the name must be inside that provider's zone, checked here so the
	// mistake surfaces at `host add` rather than on the first update.
	if _, err := host.RelativeName(cfg.Zone); err != nil {
		admin.WriteError(w, admin.Errorf(http.StatusBadRequest, "%v", err))

		return
	}

	if err := s.state.Hosts.Add(ctx, host); err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	stored, err := s.state.Hosts.Get(ctx, host.Name)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	admin.WriteJSON(w, http.StatusCreated, stored)
}

func (s *Server) adminHostRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	if err := s.state.Hosts.Remove(ctx, name); err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	// A host's credentials must not outlive it: a token for a removed host
	// would otherwise authenticate successfully and then fail on the host
	// lookup, which is a confusing state to leave behind.
	revoked, err := s.state.Tokens.RevokeAllFor(ctx, name)
	if err != nil {
		s.log.Error("host removed but its tokens could not be revoked", "host", name, "error", err)
	}

	if revoked > 0 {
		s.log.Info("revoked the removed host's tokens", "host", name, "tokens", revoked)
	}

	admin.WriteJSON(w, http.StatusNoContent, nil)
}

// TokenRequest is the body of `token create`.
type TokenRequest struct {
	Host  string `json:"host"`
	Label string `json:"label,omitempty"`
}

// TokenResponse is what `token create` and `token rotate` return.
//
// Value is populated exactly once, here. It is never stored and never
// retrievable afterwards, which is the point.
type TokenResponse struct {
	app.Token

	Value string `json:"value"`
}

func (s *Server) adminTokenList(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.state.Tokens.List(r.Context(), r.URL.Query().Get("host"))
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	if tokens == nil {
		tokens = []app.Token{}
	}

	admin.WriteJSON(w, http.StatusOK, tokens)
}

func (s *Server) adminTokenCreate(w http.ResponseWriter, r *http.Request) {
	var req TokenRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	ctx := r.Context()

	// A token for a host that does not exist could never be used, so refusing
	// is more useful than issuing one.
	if _, err := s.state.Hosts.Get(ctx, req.Host); err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	value, token, err := s.state.Tokens.Create(ctx, req.Host, req.Label)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	s.state.Publish(ctx, app.TokenCreated(token.Host, token.ID, peerName(r)))

	admin.WriteJSON(w, http.StatusCreated, TokenResponse{Token: token, Value: value})
}

func (s *Server) adminTokenRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	token, err := s.state.Tokens.Revoke(ctx, r.PathValue("id"))
	if err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	s.state.Publish(ctx, app.TokenRevoked(token.Host, token.ID, peerName(r)))

	admin.WriteJSON(w, http.StatusNoContent, nil)
}

func (s *Server) adminTokenRotate(w http.ResponseWriter, r *http.Request) {
	var req TokenRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	ctx := r.Context()
	oldID := r.PathValue("id")

	value, token, err := s.state.Tokens.Rotate(ctx, oldID, req.Label)
	if err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	s.state.Publish(ctx, app.TokenCreated(token.Host, token.ID, peerName(r)))
	s.state.Publish(ctx, app.TokenRevoked(token.Host, oldID, peerName(r)))

	admin.WriteJSON(w, http.StatusCreated, TokenResponse{Token: token, Value: value})
}

// ProviderResponse is one provider in `provider list`, with credentials
// redacted.
type ProviderResponse struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Zone     string            `json:"zone"`
	Settings map[string]string `json:"settings"`
}

func (s *Server) adminProviderList(w http.ResponseWriter, r *http.Request) {
	configs, err := s.state.Providers.List(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	out := make([]ProviderResponse, 0, len(configs))
	for _, cfg := range configs {
		// Redacted, always. `provider list` must never print a credential, and
		// building the response from the redacted map rather than the raw one
		// means a new setting cannot leak by being forgotten here.
		out = append(out, ProviderResponse{
			Name:     cfg.Name,
			Kind:     cfg.Kind,
			Zone:     cfg.Zone,
			Settings: cfg.Redacted(),
		})
	}

	admin.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) adminProviderAdd(w http.ResponseWriter, r *http.Request) {
	var cfg provider.Config
	if err := admin.DecodeJSON(w, r, &cfg); err != nil {
		admin.WriteError(w, err)

		return
	}

	if err := s.state.Providers.Add(r.Context(), cfg); err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	admin.WriteJSON(w, http.StatusCreated, ProviderResponse{
		Name:     cfg.Name,
		Kind:     cfg.Kind,
		Zone:     cfg.Zone,
		Settings: cfg.Redacted(),
	})
}

func (s *Server) adminProviderRemove(w http.ResponseWriter, r *http.Request) {
	err := s.state.Providers.Remove(r.Context(), r.PathValue("name"), s.state.Hosts)
	if err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	admin.WriteJSON(w, http.StatusNoContent, nil)
}

// TestResponse is the result of a `provider test` or `notifier test`.
type TestResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

func (s *Server) adminProviderTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	cfg, err := s.state.Providers.Get(ctx, name)
	if err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	instance, err := provider.New(cfg)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	verifier, ok := instance.(provider.Verifier)
	if !ok {
		// Reported honestly rather than faked. A `provider test` that always
		// passes is worse than one that says it cannot check.
		admin.WriteJSON(w, http.StatusOK, TestResponse{
			OK:      false,
			Message: "this provider cannot be verified without writing to the zone, so nothing was checked",
		})

		return
	}

	// A timeout of protean's own, not the request's: an administrator pressing
	// Ctrl-C should not leave a provider call running on unbounded, and a
	// provider that never answers must not hold the admin socket.
	testCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()

	if err := verifier.Verify(testCtx, cfg.Zone); err != nil {
		s.state.Publish(ctx, app.ProviderFailed(name, err))

		admin.WriteJSON(w, http.StatusOK, TestResponse{OK: false, Message: err.Error()})

		return
	}

	admin.WriteJSON(w, http.StatusOK, TestResponse{
		OK:      true,
		Message: "credentials accepted and zone " + cfg.Zone + " is readable",
	})
}

// NotifierResponse is one notifier in `notifier list`, with credentials
// redacted.
type NotifierResponse struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Settings map[string]string `json:"settings"`
}

func (s *Server) adminNotifierList(w http.ResponseWriter, r *http.Request) {
	configs, err := s.state.Notifiers.List(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	out := make([]NotifierResponse, 0, len(configs))
	for _, cfg := range configs {
		out = append(out, NotifierResponse{
			Name:     cfg.Name,
			Kind:     cfg.Kind,
			Settings: cfg.Redacted(),
		})
	}

	admin.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) adminNotifierAdd(w http.ResponseWriter, r *http.Request) {
	var cfg notify.Config
	if err := admin.DecodeJSON(w, r, &cfg); err != nil {
		admin.WriteError(w, err)

		return
	}

	ctx := r.Context()

	if err := s.state.Notifiers.Add(ctx, cfg, s.state.Secret); err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	// Subscribed immediately, so the notifier works without a restart. A
	// freshly added notifier that stays silent until the next restart looks
	// broken.
	notifier, err := notify.New(cfg, s.state.Secret)
	if err == nil {
		s.state.Bus.Subscribe(notifier)
	}

	admin.WriteJSON(w, http.StatusCreated, NotifierResponse{
		Name:     cfg.Name,
		Kind:     cfg.Kind,
		Settings: cfg.Redacted(),
	})
}

func (s *Server) adminNotifierRemove(w http.ResponseWriter, r *http.Request) {
	if err := s.state.Notifiers.Remove(r.Context(), r.PathValue("name")); err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	// The bus keeps the subscription until the next restart. Removing a live
	// subscription would mean the bus holding a mutable registry keyed by
	// name, and the cost of not doing it is one notifier that keeps delivering
	// until restart - which is why the response says so rather than pretending
	// otherwise.
	admin.WriteJSON(w, http.StatusOK, TestResponse{
		OK:      true,
		Message: "notifier removed; it stops receiving events after the next server restart",
	})
}

func (s *Server) adminNotifierTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	cfg, err := s.state.Notifiers.Get(ctx, name)
	if err != nil {
		admin.WriteError(w, s.translate(err))

		return
	}

	notifier, err := notify.New(cfg, s.state.Secret)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	// Delivered directly rather than through the outbox: `notifier test` must
	// report the outcome synchronously, and a queued event would answer
	// "accepted" whether or not the relay works.
	testCtx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()

	probe := event.New(event.Type("notifier.test"), name, "This is a test notification from protean.")
	if err := notifier.Deliver(testCtx, probe); err != nil {
		admin.WriteJSON(w, http.StatusOK, TestResponse{OK: false, Message: err.Error()})

		return
	}

	admin.WriteJSON(w, http.StatusOK, TestResponse{OK: true, Message: "test notification delivered"})
}

// ConfigurationView is the whole active configuration: the bootstrap values
// the server was started with, and the runtime settings stored in the database.
//
// Both halves together, because "what is this server actually doing" is one
// question and answering it should not require knowing which half a value
// lives in - or running `config get` once per key.
type ConfigurationView struct {
	// Bootstrap is what `server start` was given: listen address, paths, TLS
	// mode, trusted proxies. Credentials are not among them - the secret is
	// not part of the configuration struct at all.
	Bootstrap map[string]string `json:"bootstrap"`

	// Settings are the runtime-configurable values.
	Settings []ConfigEntry `json:"settings"`

	// Version identifies the running server, so a captured view is
	// attributable to a build.
	Version string `json:"version"`

	// Counts are the sizes of the stored collections, which is the other thing
	// an operator wants at a glance.
	Counts ConfigurationCounts `json:"counts"`
}

// ConfigurationCounts summarises what the database holds.
type ConfigurationCounts struct {
	Hosts     int `json:"hosts"`
	Tokens    int `json:"tokens"`
	Providers int `json:"providers"`
	Notifiers int `json:"notifiers"`
	Pending   int `json:"outbox_pending"`
	Dead      int `json:"outbox_dead"`
}

func (s *Server) adminConfigurationView(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	values := settings.All()

	entries := make([]ConfigEntry, 0, len(values))
	for _, name := range app.SettingNames() {
		help, _ := app.SettingHelp(name)
		entries = append(entries, ConfigEntry{Name: name, Value: values[name], Help: help})
	}

	counts, err := s.configurationCounts(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	admin.WriteJSON(w, http.StatusOK, ConfigurationView{
		Bootstrap: s.state.Config.Redacted(),
		Settings:  entries,
		Version:   s.state.Stamp.Version,
		Counts:    counts,
	})
}

// configurationCounts gathers the collection sizes.
func (s *Server) configurationCounts(ctx context.Context) (ConfigurationCounts, error) {
	hosts, err := s.state.Hosts.List(ctx)
	if err != nil {
		return ConfigurationCounts{}, err
	}

	tokens, err := s.state.Tokens.List(ctx, "")
	if err != nil {
		return ConfigurationCounts{}, err
	}

	providers, err := s.state.Providers.List(ctx)
	if err != nil {
		return ConfigurationCounts{}, err
	}

	notifiers, err := s.state.Notifiers.List(ctx)
	if err != nil {
		return ConfigurationCounts{}, err
	}

	pending, dead, err := s.state.Outbox.Counts(ctx)
	if err != nil {
		return ConfigurationCounts{}, err
	}

	return ConfigurationCounts{
		Hosts:     len(hosts),
		Tokens:    len(tokens),
		Providers: len(providers),
		Notifiers: len(notifiers),
		Pending:   pending,
		Dead:      dead,
	}, nil
}

// ConfigEntry is one runtime setting.
type ConfigEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Help  string `json:"help,omitempty"`
}

// ConfigSetRequest is the body of `config set`.
type ConfigSetRequest struct {
	Value string `json:"value"`
}

func (s *Server) adminConfigList(w http.ResponseWriter, r *http.Request) {
	settings, err := s.state.LoadSettings(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	values := settings.All()

	out := make([]ConfigEntry, 0, len(values))
	for _, name := range app.SettingNames() {
		help, _ := app.SettingHelp(name)
		out = append(out, ConfigEntry{Name: name, Value: values[name], Help: help})
	}

	admin.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) adminConfigGet(w http.ResponseWriter, r *http.Request) {
	settings, err := s.state.LoadSettings(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	name := r.PathValue("name")

	value, err := settings.Get(name)
	if err != nil {
		admin.WriteError(w, admin.Errorf(http.StatusNotFound, "%v", err))

		return
	}

	help, _ := app.SettingHelp(name)

	admin.WriteJSON(w, http.StatusOK, ConfigEntry{Name: name, Value: value, Help: help})
}

func (s *Server) adminConfigSet(w http.ResponseWriter, r *http.Request) {
	var req ConfigSetRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	ctx := r.Context()

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	name := r.PathValue("name")

	updated, err := settings.Set(name, req.Value)
	if err != nil {
		admin.WriteError(w, admin.Errorf(http.StatusBadRequest, "%v", err))

		return
	}

	if err := s.state.ApplySettings(ctx, updated); err != nil {
		admin.WriteError(w, err)

		return
	}

	value, _ := updated.Get(name)
	help, _ := app.SettingHelp(name)

	s.log.Info("setting changed", "setting", name, "value", value, "by", peerName(r))

	admin.WriteJSON(w, http.StatusOK, ConfigEntry{Name: name, Value: value, Help: help})
}

// OutboxResponse summarises the notification outbox.
type OutboxResponse struct {
	Pending int           `json:"pending"`
	Dead    int           `json:"dead"`
	Entries []event.Entry `json:"entries,omitempty"`
}

func (s *Server) adminOutboxList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	pending, dead, err := s.state.Outbox.Counts(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	response := OutboxResponse{Pending: pending, Dead: dead}

	// The dead entries are the interesting ones after an incident: an alert
	// that never arrived is exactly what an operator goes looking for. The
	// pending ones answer the other question - what is stuck right now.
	switch {
	case r.URL.Query().Get("dead") == "true":
		entries, err := s.state.Outbox.Dead(ctx, 100)
		if err != nil {
			admin.WriteError(w, err)

			return
		}

		response.Entries = entries
	case r.URL.Query().Get("pending") == "true":
		entries, err := s.state.Outbox.Pending(ctx, 100)
		if err != nil {
			admin.WriteError(w, err)

			return
		}

		response.Entries = entries
	}

	admin.WriteJSON(w, http.StatusOK, response)
}

// translate maps the app package's sentinel errors onto admin errors with the
// right status and a hint.
//
// Done in one place so every handler reports the same condition identically -
// a "not found" that is a 500 in one route and a 404 in another is the kind of
// inconsistency that makes a CLI unpredictable.
func (s *Server) translate(err error) error {
	switch {
	case errors.Is(err, app.ErrHostNotFound):
		return admin.Errorf(http.StatusNotFound, "%v", err).
			WithHint("run `protean host list` to see the configured hosts")
	case errors.Is(err, app.ErrHostExists):
		return admin.Errorf(http.StatusConflict, "%v", err).
			WithHint("remove it first, or pick a different name")
	case errors.Is(err, app.ErrTokenNotFound):
		return admin.Errorf(http.StatusNotFound, "%v", err).
			WithHint("run `protean token list` to see the token IDs")
	case errors.Is(err, app.ErrTokenMismatch):
		return admin.Errorf(http.StatusForbidden, "%v", err)
	case errors.Is(err, app.ErrProviderNotFound):
		return admin.Errorf(http.StatusNotFound, "%v", err).
			WithHint("run `protean provider list` to see the configured providers")
	case errors.Is(err, app.ErrProviderExists):
		return admin.Errorf(http.StatusConflict, "%v", err)
	case errors.Is(err, app.ErrProviderInUse):
		return admin.Errorf(http.StatusConflict, "%v", err).
			WithHint("remove or reassign those hosts first")
	case errors.Is(err, app.ErrNotifierNotFound):
		return admin.Errorf(http.StatusNotFound, "%v", err).
			WithHint("run `protean notifier list` to see the configured notifiers")
	case errors.Is(err, app.ErrNotifierExists):
		return admin.Errorf(http.StatusConflict, "%v", err)
	case errors.Is(err, provider.ErrUnknownKind), errors.Is(err, notify.ErrUnknownKind):
		return admin.Errorf(http.StatusBadRequest, "%v", err).
			WithHint("providers and notifiers are compiled in, so this binary supports a fixed set")
	default:
		// Anything unrecognised is a 400 rather than a 500 when it came from a
		// validating constructor, but this cannot tell those apart, so it
		// stays a 500 and the message carries the detail.
		return err
	}
}

// peerName renders the administrator for an audit record and an event field.
//
// The identity comes from the kernel via SO_PEERCRED, so it is the account that
// actually ran the command rather than anything the request claimed.
func peerName(r *http.Request) string {
	peer, ok := admin.PeerFrom(r.Context())
	if !ok {
		return "unknown"
	}

	return peer.String()
}
