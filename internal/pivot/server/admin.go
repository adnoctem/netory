package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/internal/pivot/rules"
	"github.com/adnoctem/netory/pkg/admin"
	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/notify"
)

// APIPrefix versions the admin API.
//
// The CLI and the server ship in the same binary, so they normally match - but
// on a rolling deployment the CLI reached through `kubectl exec` may be a
// different build from the replica answering, and a prefix makes a future
// incompatible change a new prefix rather than a silently misinterpreted
// request.
const APIPrefix = "/v1"

// maxRuleDocumentBytes bounds a rule document upload.
const maxRuleDocumentBytes = int64(rules.MaxDocumentBytes) + (16 << 10)

// Multipart field names for a rule document upload.
const (
	FieldRules  = "rules"
	FieldClient = "client"
)

// adminHandler builds the admin routes.
//
// Every route is a thin translation between the CLI's intent and the
// application layer. That keeps the socket surface auditable: the interesting
// question about an admin API is what it exposes, and this file is the answer
// in full.
//
// Every mutation ends by invalidating, which bumps the rule version and
// announces it. That is what makes a change made through
// one replica's socket applies to all of them - and it is why there is no
// route here that writes without it.
func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+APIPrefix+"/meta", s.adminMeta)

	mux.HandleFunc("GET "+APIPrefix+"/clients", s.adminClientList)
	mux.HandleFunc("POST "+APIPrefix+"/clients", s.adminClientAdd)
	mux.HandleFunc("GET "+APIPrefix+"/clients/{id}", s.adminClientGet)
	mux.HandleFunc("DELETE "+APIPrefix+"/clients/{id}", s.adminClientRemove)
	mux.HandleFunc("POST "+APIPrefix+"/clients/{id}/rotate", s.adminClientRotate)
	mux.HandleFunc("POST "+APIPrefix+"/clients/{id}/disable", s.adminClientDisable)
	mux.HandleFunc("POST "+APIPrefix+"/clients/{id}/enable", s.adminClientEnable)
	mux.HandleFunc("POST "+APIPrefix+"/clients/{id}/backend", s.adminClientBackend)
	mux.HandleFunc("POST "+APIPrefix+"/clients/{id}/limit", s.adminClientLimit)
	mux.HandleFunc("POST "+APIPrefix+"/clients/{id}/backend/test", s.adminBackendTest)

	mux.HandleFunc("GET "+APIPrefix+"/tokens", s.adminTokenList)
	mux.HandleFunc("POST "+APIPrefix+"/tokens", s.adminTokenCreate)
	mux.HandleFunc("DELETE "+APIPrefix+"/tokens/{hash}", s.adminTokenRevoke)

	// A distinct path rather than /rules/{name}, since the rule document is
	// a single thing rather than a collection.
	mux.HandleFunc("GET "+APIPrefix+"/rules", s.adminRulesGet)
	mux.HandleFunc("POST "+APIPrefix+"/rules", s.adminRulesApply)
	mux.HandleFunc("POST "+APIPrefix+"/rules/test", s.adminRulesTest)

	mux.HandleFunc("GET "+APIPrefix+"/notifiers", s.adminNotifierList)
	mux.HandleFunc("POST "+APIPrefix+"/notifiers", s.adminNotifierAdd)
	mux.HandleFunc("DELETE "+APIPrefix+"/notifiers/{name}", s.adminNotifierRemove)
	mux.HandleFunc("POST "+APIPrefix+"/notifiers/{name}/test", s.adminNotifierTest)

	mux.HandleFunc("GET "+APIPrefix+"/configuration", s.adminConfigurationView)
	mux.HandleFunc("GET "+APIPrefix+"/config", s.adminConfigList)
	mux.HandleFunc("GET "+APIPrefix+"/config/{name}", s.adminConfigGet)
	mux.HandleFunc("PUT "+APIPrefix+"/config/{name}", s.adminConfigSet)

	mux.HandleFunc("GET "+APIPrefix+"/outbox", s.adminOutboxList)
	mux.HandleFunc("GET "+APIPrefix+"/audit", s.adminAuditList)
	mux.HandleFunc("POST "+APIPrefix+"/cache/purge", s.adminCachePurge)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		admin.WriteError(w, admin.Errorf(http.StatusNotFound, "no such admin endpoint: %s %s",
			r.Method, r.URL.Path).
			WithHint("this usually means the CLI is a different version from the replica answering"))
	})

	return mux
}

// MetaResponse is what `pivot version` reports about the replica it reached.
type MetaResponse struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	CommitSHA string `json:"commit_sha"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`

	// Replica is which process answered, which on a multi-replica deployment
	// is the first thing an operator needs to know about any answer they got.
	Replica string `json:"replica"`

	Notifiers []string `json:"notifiers"`

	// RuleVersion is the rule version this replica is serving, so two
	// replicas disagreeing is visible rather than mysterious.
	RuleVersion int64 `json:"rule_version"`

	Clients int    `json:"clients"`
	Backend string `json:"backend,omitempty"`
}

func (s *Server) adminMeta(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stamps := s.state.Stamp
	table := s.state.Reloader.Table()

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	clients, err := s.state.Clients.List(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	admin.WriteJSON(w, http.StatusOK, MetaResponse{
		Name:        app.Name,
		Version:     stamps.Version,
		CommitSHA:   stamps.CommitSHA,
		BuildDate:   stamps.BuildDate,
		GoVersion:   stamps.GoVersion,
		Platform:    stamps.Platform,
		Replica:     s.state.Config.Replica,
		Notifiers:   notify.Kinds(),
		RuleVersion: table.Version,
		Clients:     len(clients),
		Backend:     backendHost(settings.BackendURL),
	})
}

// ClientRequest is the body of `client add`.
type ClientRequest struct {
	Name    string             `json:"name"`
	Backend auth.BackendConfig `json:"backend"`

	// Burst and PerSecond are the client's rate limit. Both zero means the
	// instance default.
	Burst     int     `json:"burst,omitempty"`
	PerSecond float64 `json:"per_second,omitempty"`
}

// ClientResponse is one client, with every credential removed.
type ClientResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Backend   map[string]string `json:"backend"`
	RateLimit string            `json:"rate_limit"`
	Rules     string            `json:"rules"`
	Disabled  bool              `json:"disabled"`
	CreatedAt time.Time         `json:"created_at"`
	CreatedBy string            `json:"created_by"`

	// Secret is set only in the response to `client add` and to a rotation.
	// It is shown once and never stored in recoverable form.
	Secret string `json:"secret,omitempty"`
}

func clientResponse(client app.Client) ClientResponse {
	redacted := client.Redacted()

	return ClientResponse{
		ID:        client.ID,
		Name:      client.Name,
		Backend:   client.Backend.Redacted(),
		RateLimit: client.RateLimit.String(),
		Rules:     redacted["rules"],
		Disabled:  client.Disabled,
		CreatedAt: client.CreatedAt,
		CreatedBy: client.CreatedBy,
	}
}

func (s *Server) adminClientList(w http.ResponseWriter, r *http.Request) {
	clients, err := s.state.Clients.List(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	out := make([]ClientResponse, 0, len(clients))
	for _, client := range clients {
		out = append(out, clientResponse(client))
	}

	admin.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) adminClientAdd(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req ClientRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	created, secret, err := s.state.Clients.Create(ctx, app.Client{
		Name:      req.Name,
		Backend:   req.Backend,
		RateLimit: app.RateLimit{Capacity: req.Burst, PerSecond: req.PerSecond},
		CreatedBy: peerName(r),
	})
	if err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	s.state.Audit.Admin(ctx, peerName(r), "client.add", created.ID, map[string]string{
		"name":    created.Name,
		"backend": string(created.Backend.Mode),
	})

	if err := s.state.Invalidate(ctx); err != nil {
		admin.WriteError(w, err)

		return
	}

	response := clientResponse(created)
	response.Secret = secret

	admin.WriteJSON(w, http.StatusCreated, response)
}

func (s *Server) adminClientGet(w http.ResponseWriter, r *http.Request) {
	client, err := s.state.Clients.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	admin.WriteJSON(w, http.StatusOK, clientResponse(client))
}

func (s *Server) adminClientRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	// The tokens go first. A client whose record is gone must not keep
	// working through a token issued before it went, and doing it in this
	// order means a crash between the two leaves tokens for a client that
	// still exists rather than a client that does not.
	revoked, err := s.state.Tokens.RevokeForClient(ctx, id)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	if err := s.state.Clients.Remove(ctx, id); err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	// The rate-limit bucket goes too, so a new client that happened to get
	// the same id would not inherit a spent bucket. Best-effort: the bucket
	// expires on its own.
	if err := s.state.Limiter.Reset(ctx, id); err != nil {
		s.log.Warn("could not reset the rate limit of a removed client",
			"client", id, "error", err)
	}

	s.state.ForgetBackend(id)

	s.state.Audit.Admin(ctx, peerName(r), "client.remove", id, map[string]string{
		"tokens_revoked": strconv.Itoa(revoked),
	})

	if err := s.state.Invalidate(ctx); err != nil {
		admin.WriteError(w, err)

		return
	}

	admin.WriteJSON(w, http.StatusOK, TestResponse{
		OK:      true,
		Message: "client removed, " + strconv.Itoa(revoked) + " token(s) revoked",
	})
}

func (s *Server) adminClientRotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	secret, err := s.state.Clients.RotateSecret(ctx, id)
	if err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	s.state.Audit.Admin(ctx, peerName(r), "client.rotate", id, nil)

	if err := s.state.Invalidate(ctx); err != nil {
		admin.WriteError(w, err)

		return
	}

	admin.WriteJSON(w, http.StatusOK, ClientResponse{ID: id, Secret: secret})
}

func (s *Server) adminClientDisable(w http.ResponseWriter, r *http.Request) {
	s.setDisabled(w, r, true)
}

func (s *Server) adminClientEnable(w http.ResponseWriter, r *http.Request) {
	s.setDisabled(w, r, false)
}

// setDisabled suspends or restores a client.
func (s *Server) setDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	ctx := r.Context()
	id := r.PathValue("id")

	if err := s.state.Clients.SetDisabled(ctx, id, disabled); err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	action := "client.enable"
	message := "client enabled"

	if disabled {
		action = "client.disable"
		message = "client disabled"

		// A suspended client's tokens are revoked, or it would keep working
		// until they expired - which is not what "disabled" means to the
		// person who typed it.
		revoked, err := s.state.Tokens.RevokeForClient(ctx, id)
		if err != nil {
			admin.WriteError(w, err)

			return
		}

		message += ", " + strconv.Itoa(revoked) + " token(s) revoked"
	}

	s.state.Audit.Admin(ctx, peerName(r), action, id, nil)

	if err := s.state.Invalidate(ctx); err != nil {
		admin.WriteError(w, err)

		return
	}

	admin.WriteJSON(w, http.StatusOK, TestResponse{OK: true, Message: message})
}

func (s *Server) adminClientBackend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var cfg auth.BackendConfig
	if err := admin.DecodeJSON(w, r, &cfg); err != nil {
		admin.WriteError(w, err)

		return
	}

	client, err := s.state.Clients.Get(ctx, id)
	if err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	client.Backend = cfg

	if err := s.state.Clients.Update(ctx, client); err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	// The cached authenticator goes, so the new credentials take effect on
	// the next request rather than when the old backend token expires.
	s.state.ForgetBackend(id)

	s.state.Audit.Admin(ctx, peerName(r), "client.backend", id, map[string]string{
		"mode": string(cfg.Mode),
	})

	if err := s.state.Invalidate(ctx); err != nil {
		admin.WriteError(w, err)

		return
	}

	admin.WriteJSON(w, http.StatusOK, TestResponse{OK: true, Message: "backend credentials replaced"})
}

// LimitRequest is the body of `client limit`.
type LimitRequest struct {
	Burst     int     `json:"burst"`
	PerSecond float64 `json:"per_second"`
}

func (s *Server) adminClientLimit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req LimitRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	client, err := s.state.Clients.Get(ctx, id)
	if err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	client.RateLimit = app.RateLimit{Capacity: req.Burst, PerSecond: req.PerSecond}

	if err := s.state.Clients.Update(ctx, client); err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	// The old bucket goes, so a raised limit takes effect now rather than
	// after the old one refills at the old rate.
	if err := s.state.Limiter.Reset(ctx, id); err != nil {
		s.log.Warn("could not reset the rate limit", "client", id, "error", err)
	}

	s.state.Audit.Admin(ctx, peerName(r), "client.limit", id, map[string]string{
		"limit": client.RateLimit.String(),
	})

	if err := s.state.Invalidate(ctx); err != nil {
		admin.WriteError(w, err)

		return
	}

	admin.WriteJSON(w, http.StatusOK, TestResponse{
		OK:      true,
		Message: "rate limit set to " + client.RateLimit.String(),
	})
}

// adminBackendTest checks that the backend accepts one client's credentials.
//
// A real request rather than a validation pass, because "the configuration
// parses" is not the question. What an operator wants to know is whether the
// backend will accept these credentials, and the only way to find that out is
// to ask it.
func (s *Server) adminBackendTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	client, err := s.state.Clients.Get(ctx, id)
	if err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	if settings.BackendURL == "" {
		admin.WriteError(w, admin.Errorf(http.StatusUnprocessableEntity,
			"no backend URL is configured").
			WithHint("set one with `pivot backend set https://…`"))

		return
	}

	backend, err := s.state.Backend(client)
	if err != nil {
		admin.WriteError(w, admin.Errorf(http.StatusUnprocessableEntity, "%v", err))

		return
	}

	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, settings.BackendURL+"/", nil)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	// In oauth2 mode this is the whole test: Authorize fetches a token, so a
	// rejected credential fails here with a message from the backend.
	if err := backend.Authorize(ctx, probe); err != nil {
		s.state.Audit.Admin(ctx, peerName(r), "backend.test", id, map[string]string{
			"result": "credentials rejected",
		})

		admin.WriteJSON(w, http.StatusOK, TestResponse{
			OK:      false,
			Message: "the backend rejected the credentials: " + err.Error(),
		})

		return
	}

	resp, err := s.backend.Do(probe)
	if err != nil {
		admin.WriteJSON(w, http.StatusOK, TestResponse{
			OK:      false,
			Message: "the backend could not be reached: " + err.Error(),
		})

		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	s.state.Audit.Admin(ctx, peerName(r), "backend.test", id, map[string]string{
		"status": strconv.Itoa(resp.StatusCode),
	})

	// A 401 or 403 means the credentials were rejected. Anything else means
	// the backend was reached and answered, which is what was being tested -
	// a 404 on "/" is a perfectly healthy API that simply has no root route,
	// and reporting that as a failure would send an operator looking for a
	// problem that is not there.
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		admin.WriteJSON(w, http.StatusOK, TestResponse{
			OK: false,
			Message: fmt.Sprintf(
				"the backend answered %d, so it rejected the credentials", resp.StatusCode),
		})
	default:
		admin.WriteJSON(w, http.StatusOK, TestResponse{
			OK: true,
			Message: fmt.Sprintf(
				"the backend accepted the credentials (it answered %d to GET /, which only has to "+
					"mean it was reached)", resp.StatusCode),
		})
	}
}

// TokenRequest is the body of `token create`.
type TokenRequest struct {
	ClientID string `json:"client_id"`
	Label    string `json:"label,omitempty"`

	// Lifetime overrides the configured token lifetime.
	Lifetime string `json:"lifetime,omitempty"`
}

// TokenResponse is one token record. The token itself appears only in the
// response to `token create`.
type TokenResponse struct {
	Hash      string    `json:"hash"`
	ClientID  string    `json:"client_id"`
	Label     string    `json:"label,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedBy  string    `json:"issued_by"`
	Token     string    `json:"token,omitempty"`
}

func (s *Server) adminTokenList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var (
		tokens []app.Token
		err    error
	)

	if client := r.URL.Query().Get("client"); client != "" {
		tokens, err = s.state.Tokens.ListFor(ctx, client)
	} else {
		tokens, err = s.state.Tokens.List(ctx)
	}

	if err != nil {
		admin.WriteError(w, err)

		return
	}

	out := make([]TokenResponse, 0, len(tokens))
	for _, token := range tokens {
		out = append(out, TokenResponse{
			Hash:      token.Hash,
			ClientID:  token.ClientID,
			Label:     token.Label,
			IssuedAt:  token.IssuedAt,
			ExpiresAt: token.ExpiresAt,
			IssuedBy:  token.IssuedBy,
		})
	}

	admin.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) adminTokenCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req TokenRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	client, err := s.state.Clients.Get(ctx, req.ClientID)
	if err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	lifetime := settings.TokenLifetime

	if req.Lifetime != "" {
		parsed, parseErr := time.ParseDuration(req.Lifetime)
		if parseErr != nil {
			admin.WriteError(w, admin.Errorf(http.StatusBadRequest,
				"%q is not a duration", req.Lifetime))

			return
		}

		lifetime = parsed
	}

	value, token, err := s.state.Tokens.Issue(
		ctx, client.ID, req.Label, "", peerName(r), lifetime)
	if err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	s.state.Audit.Admin(ctx, peerName(r), "token.create", client.ID, map[string]string{
		"label":      req.Label,
		"expires_at": token.ExpiresAt.Format(time.RFC3339),
	})

	admin.WriteJSON(w, http.StatusCreated, TokenResponse{
		Hash:      token.Hash,
		ClientID:  token.ClientID,
		Label:     token.Label,
		IssuedAt:  token.IssuedAt,
		ExpiresAt: token.ExpiresAt,
		IssuedBy:  token.IssuedBy,
		Token:     value,
	})
}

func (s *Server) adminTokenRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	hash := r.PathValue("hash")

	if err := s.state.Tokens.RevokeHash(ctx, hash); err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	s.state.Audit.Admin(ctx, peerName(r), "token.revoke", hash, nil)

	w.WriteHeader(http.StatusNoContent)
}

// RulesResponse is the stored rule document and what this replica compiled
// from it.
type RulesResponse struct {
	Version int64    `json:"version"`
	Deny    int      `json:"deny"`
	Allow   int      `json:"allow"`
	Routes  int      `json:"routes"`
	Entries []string `json:"entries"`

	// Document is the stored YAML, for `rules list --yaml`.
	Document string `json:"document,omitempty"`
}

func (s *Server) adminRulesGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	doc, err := s.state.Rules.Global(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	table := s.state.Reloader.Table()
	deny, allow, routes := table.Global.Counts()

	response := RulesResponse{
		Version: table.Version,
		Deny:    deny,
		Allow:   allow,
		Routes:  routes,
		Entries: table.Global.Describe(),
	}

	if r.URL.Query().Get("document") == "true" {
		encoded, encodeErr := rules.Encode(doc)
		if encodeErr != nil {
			admin.WriteError(w, encodeErr)

			return
		}

		response.Document = string(encoded)
	}

	admin.WriteJSON(w, http.StatusOK, response)
}

func (s *Server) adminRulesApply(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	form, err := admin.ParseUpload(w, r, maxRuleDocumentBytes)
	if err != nil {
		admin.WriteError(w, err)

		return
	}
	defer func() {
		if form != nil {
			_ = form.RemoveAll()
		}
	}()

	_, document, ok, err := admin.UploadedFile(form, FieldRules)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	if !ok {
		admin.WriteError(w, admin.Errorf(http.StatusBadRequest,
			"no %s part in the request", FieldRules))

		return
	}

	doc, err := rules.Parse(document)
	if err != nil {
		admin.WriteError(w, admin.Errorf(http.StatusUnprocessableEntity, "%v", err).
			WithHint("run `pivot rules validate <file>` to check a document without a server"))

		return
	}

	target := admin.UploadedField(form, FieldClient)

	if target == "" {
		version, err := s.state.Rules.SetGlobal(ctx, doc)
		if err != nil {
			admin.WriteError(w, admin.Errorf(http.StatusUnprocessableEntity, "%v", err))

			return
		}

		s.state.Audit.Admin(ctx, peerName(r), "rules.apply", "global", map[string]string{
			"version": strconv.FormatInt(version, 10),
			"deny":    strconv.Itoa(len(doc.Rules.Deny)),
			"allow":   strconv.Itoa(len(doc.Rules.Allow)),
		})
	} else {
		client, err := s.state.Clients.Get(ctx, target)
		if err != nil {
			admin.WriteError(w, translate(err))

			return
		}

		client.Rules = &doc

		if err := s.state.Clients.Update(ctx, client); err != nil {
			admin.WriteError(w, admin.Errorf(http.StatusUnprocessableEntity, "%v", err))

			return
		}

		s.state.Audit.Admin(ctx, peerName(r), "rules.apply", target, map[string]string{
			"deny":  strconv.Itoa(len(doc.Rules.Deny)),
			"allow": strconv.Itoa(len(doc.Rules.Allow)),
		})
	}

	if err := s.state.Invalidate(ctx); err != nil {
		admin.WriteError(w, err)

		return
	}

	s.adminRulesGet(w, r)
}

// RuleTestRequest is the body of `rules test`.
type RuleTestRequest struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	ClientID string `json:"client_id,omitempty"`
}

// RuleTestResponse is what `rules test` reports.
type RuleTestResponse struct {
	Method string `json:"method"`

	// Path is the normalized path, which is the one the rules matched. Worth
	// returning: the difference between what was typed and what was matched
	// is exactly what path normalization is about.
	Path       string `json:"path"`
	Normalized bool   `json:"normalized"`

	Allowed bool   `json:"allowed"`
	Outcome string `json:"outcome"`
	Rule    string `json:"rule,omitempty"`
	Scope   string `json:"scope,omitempty"`

	// Cacheable reports the route's cache configuration, since "why is this
	// not being cached" is the other question this command gets asked.
	Cacheable bool   `json:"cacheable"`
	CacheTTL  string `json:"cache_ttl,omitempty"`
	Encrypted bool   `json:"cache_encrypted,omitempty"`
}

func (s *Server) adminRulesTest(w http.ResponseWriter, r *http.Request) {
	var req RuleTestRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}

	normalized, err := rules.Normalize(req.Path)
	if err != nil {
		admin.WriteError(w, admin.Errorf(http.StatusUnprocessableEntity, "%v", err).
			WithHint("pivot refuses an ambiguous path rather than guessing, "+
				"so this request would be answered 400 before any rule was consulted"))

		return
	}

	set := s.state.Reloader.Table().For(req.ClientID)
	decision := set.Evaluate(method, normalized)

	response := RuleTestResponse{
		Method:     method,
		Path:       normalized,
		Normalized: normalized != req.Path,
		Allowed:    decision.Allowed(),
		Outcome:    string(decision.Outcome),
		Rule:       decision.Rule,
		Scope:      string(decision.Scope),
	}

	if config, ok := set.CacheFor(method, normalized); ok {
		response.Cacheable = true
		response.CacheTTL = config.TTL.String()
		response.Encrypted = config.Encrypt
	}

	admin.WriteJSON(w, http.StatusOK, response)
}

// TestResponse is the result of an action whose effect is worth a sentence.
type TestResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// NotifierRequest is the body of `notifier add`.
type NotifierRequest struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Settings map[string]string `json:"settings"`
}

// NotifierResponse is one notifier, with credentials redacted.
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
	ctx := r.Context()

	var req NotifierRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	cfg := notify.Config{Name: req.Name, Kind: req.Kind, Settings: req.Settings}

	if err := s.state.Notifiers.Add(ctx, cfg, s.state.Secret); err != nil {
		if errors.Is(err, app.ErrNotifierExists) {
			admin.WriteError(w, admin.Errorf(http.StatusConflict, "%v", err))

			return
		}

		admin.WriteError(w, admin.Errorf(http.StatusBadRequest, "%v", err))

		return
	}

	// Subscribed on this replica now, so a notifier added in response to an
	// incident receives the next event. The other replicas pick it up when
	// they next restart - the bus holds its subscribers in a slice with no
	// way to remove one, which is the same limitation protean records.
	if notifier, err := notify.New(cfg, s.state.Secret); err == nil {
		s.state.Bus.Subscribe(notifier)
	}

	s.state.Audit.Admin(ctx, peerName(r), "notifier.add", cfg.Name, map[string]string{
		"kind": cfg.Kind,
	})

	admin.WriteJSON(w, http.StatusCreated, NotifierResponse{
		Name:     cfg.Name,
		Kind:     cfg.Kind,
		Settings: cfg.Redacted(),
	})
}

func (s *Server) adminNotifierRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	if err := s.state.Notifiers.Remove(ctx, name); err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	s.state.Audit.Admin(ctx, peerName(r), "notifier.remove", name, nil)

	admin.WriteJSON(w, http.StatusOK, TestResponse{
		OK:      true,
		Message: "notifier removed; replicas stop delivering to it after their next restart",
	})
}

func (s *Server) adminNotifierTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	cfg, err := s.state.Notifiers.Get(ctx, name)
	if err != nil {
		admin.WriteError(w, translate(err))

		return
	}

	notifier, err := notify.New(cfg, s.state.Secret)
	if err != nil {
		admin.WriteError(w, admin.Errorf(http.StatusUnprocessableEntity, "%v", err))

		return
	}

	// Delivered directly rather than through the outbox: `notifier test`
	// exists to answer "does this work", and a queued event would answer
	// "accepted" whether or not the relay works.
	probe := event.New(event.Type("notifier.test"), name,
		"This is a test notification from pivot.")

	if err := notifier.Deliver(ctx, probe); err != nil {
		// 200 with ok=false rather than a 5xx: the request was handled
		// correctly and the answer is "the transport does not work", which is
		// what was asked.
		admin.WriteJSON(w, http.StatusOK, TestResponse{OK: false, Message: err.Error()})

		return
	}

	admin.WriteJSON(w, http.StatusOK, TestResponse{
		OK:      true,
		Message: "delivered through " + cfg.Kind,
	})
}

// ConfigurationResponse is what `config view` reports: the whole active
// configuration of the replica that answered.
type ConfigurationResponse struct {
	Replica   string            `json:"replica"`
	Bootstrap map[string]string `json:"bootstrap"`
	Settings  map[string]string `json:"settings"`

	// Serving describes what this replica is doing right now, which on a
	// multi-replica deployment is per replica and worth labelling as such.
	Serving map[string]string `json:"serving"`
}

func (s *Server) adminConfigurationView(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	table := s.state.Reloader.Table()
	deny, allow, routes := table.Global.Counts()
	version, reloads, misses, builtAt := s.state.Reloader.Stats()
	inFlight, waiting, refused, limit := s.concurrency.Stats()

	cached, err := s.state.Cache.Count(ctx)
	if err != nil {
		cached = -1
	}

	pending, dead, err := s.state.Outbox.Counts(ctx)
	if err != nil {
		pending, dead = -1, -1
	}

	admin.WriteJSON(w, http.StatusOK, ConfigurationResponse{
		Replica:   s.state.Config.Replica,
		Bootstrap: s.state.Config.Redacted(),
		Settings:  settings.All(),
		Serving: map[string]string{
			"rule.version":           strconv.FormatInt(version, 10),
			"rule.deny":              strconv.Itoa(deny),
			"rule.allow":             strconv.Itoa(allow),
			"rule.cacheable_routes":  strconv.Itoa(routes),
			"rule.clients":           strconv.Itoa(table.Clients()),
			"rule.built_at":          builtAt.Format(time.RFC3339),
			"rule.reloads":           strconv.FormatInt(reloads, 10),
			"rule.reload_failures":   strconv.FormatInt(misses, 10),
			"backend.in_flight":      strconv.FormatInt(inFlight, 10),
			"backend.waiting":        strconv.FormatInt(waiting, 10),
			"backend.refused":        strconv.FormatInt(refused, 10),
			"backend.limit":          strconv.Itoa(limit),
			"backend.authenticators": strconv.Itoa(s.state.CachedBackends()),
			"coalesce.in_flight":     strconv.Itoa(s.coalescer.InFlight()),
			"coalesce.shared":        strconv.FormatInt(s.coalescer.Shared(), 10),
			"cache.entries":          strconv.Itoa(cached),
			"cache.encryption":       strconv.FormatBool(s.state.Cache.CanEncrypt()),
			"outbox.pending":         strconv.Itoa(pending),
			"outbox.dead":            strconv.Itoa(dead),
		},
	})
}

// SettingResponse is one setting.
type SettingResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Help  string `json:"help,omitempty"`
}

func (s *Server) adminConfigList(w http.ResponseWriter, r *http.Request) {
	settings, err := s.state.LoadSettings(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	values := settings.All()

	out := make([]SettingResponse, 0, len(values))
	for _, name := range app.SettingNames() {
		help, _ := app.SettingHelp(name)
		out = append(out, SettingResponse{Name: name, Value: values[name], Help: help})
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
	admin.WriteJSON(w, http.StatusOK, SettingResponse{Name: name, Value: value, Help: help})
}

// SettingRequest is the body of `config set`.
type SettingRequest struct {
	Value string `json:"value"`
}

func (s *Server) adminConfigSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SettingRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

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

	value, err := updated.Get(name)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	s.state.Audit.Admin(ctx, peerName(r), "config.set", name, map[string]string{
		"value": value,
	})

	help, _ := app.SettingHelp(name)
	admin.WriteJSON(w, http.StatusOK, SettingResponse{Name: name, Value: value, Help: help})
}

// OutboxResponse is the queue's state on this replica's view of Valkey.
type OutboxResponse struct {
	Pending int           `json:"pending"`
	Dead    int           `json:"dead"`
	Entries []event.Entry `json:"entries,omitempty"`

	// Claims reports who holds which pending entries, which on a
	// multi-replica deployment is the difference between "nothing is
	// draining" and "it is all claimed by a replica that no longer exists".
	Claims map[string]int `json:"claims,omitempty"`
}

// outboxPageSize bounds how many entries one call returns.
const outboxPageSize = 100

func (s *Server) adminOutboxList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	pending, dead, err := s.state.Outbox.Counts(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	claims, err := s.state.Outbox.Claims(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	response := OutboxResponse{Pending: pending, Dead: dead, Claims: claims}

	switch {
	case r.URL.Query().Get("dead") == "true":
		entries, err := s.state.Outbox.Dead(ctx, outboxPageSize)
		if err != nil {
			admin.WriteError(w, err)

			return
		}

		response.Entries = entries
	case r.URL.Query().Get("pending") == "true":
		entries, err := s.state.Outbox.Pending(ctx, outboxPageSize)
		if err != nil {
			admin.WriteError(w, err)

			return
		}

		response.Entries = entries
	}

	admin.WriteJSON(w, http.StatusOK, response)
}

// auditPageSize bounds how many audit records one call returns.
const auditPageSize = 200

func (s *Server) adminAuditList(w http.ResponseWriter, r *http.Request) {
	kind := app.AuditKind(r.URL.Query().Get("kind"))

	records, err := s.state.Audit.List(r.Context(), kind, auditPageSize)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	admin.WriteJSON(w, http.StatusOK, records)
}

func (s *Server) adminCachePurge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	removed, err := s.state.Cache.Purge(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	s.state.Audit.Admin(ctx, peerName(r), "cache.purge", "", map[string]string{
		"entries": strconv.Itoa(removed),
	})

	admin.WriteJSON(w, http.StatusOK, TestResponse{
		OK:      true,
		Message: strconv.Itoa(removed) + " cache entries removed",
	})
}

// translate maps the app package's sentinel errors onto admin errors with the
// right status and a hint.
func translate(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, app.ErrClientNotFound):
		return admin.Errorf(http.StatusNotFound, "%v", err).
			WithHint("run `pivot client list` to see the configured clients")
	case errors.Is(err, app.ErrClientExists):
		return admin.Errorf(http.StatusConflict, "%v", err)
	case errors.Is(err, app.ErrClientDisabled):
		return admin.Errorf(http.StatusConflict, "%v", err).
			WithHint("run `pivot client enable <id>` to restore it")
	case errors.Is(err, app.ErrTokenNotFound):
		return admin.Errorf(http.StatusNotFound, "%v", err).
			WithHint("run `pivot token list` to see the live tokens; " +
				"an expired one is already gone")
	case errors.Is(err, app.ErrTokenLifetime):
		return admin.Errorf(http.StatusBadRequest, "%v", err)
	case errors.Is(err, app.ErrNotifierNotFound):
		return admin.Errorf(http.StatusNotFound, "%v", err)
	case errors.Is(err, app.ErrNotifierExists):
		return admin.Errorf(http.StatusConflict, "%v", err)
	case errors.Is(err, rules.ErrWriteMethod):
		return admin.Errorf(http.StatusUnprocessableEntity, "%v", err).
			WithHint("pivot is read-only by construction: no rule set can grant a write")
	case errors.Is(err, rules.ErrWildcardAllow):
		return admin.Errorf(http.StatusUnprocessableEntity, "%v", err)
	default:
		return err
	}
}

// peerName renders the socket peer for an audit record.
//
// Taken from the kernel through SO_PEERCRED rather than from anything the
// request claimed, which is what makes the "who" in the audit trail worth
// recording at all.
func peerName(r *http.Request) string {
	peer, ok := admin.PeerFrom(r.Context())
	if !ok {
		return "unknown"
	}

	return peer.String()
}
