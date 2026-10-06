package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/internal/pivot/cache"
	"github.com/adnoctem/netory/internal/pivot/rules"
	"github.com/adnoctem/netory/pkg/forwarded"
)

// Headers pivot sets on its own responses.
//
// Deliberately few. §2 promises pivot is invisible to customers' clients, so
// it adds only what a client could not otherwise know: the cache state, and
// the rate-limit position. Anything else would be pivot announcing itself in a
// response that is meant to look like the backend's.
const (
	HeaderCacheStatus   = "X-Pivot-Cache"
	HeaderRateRemaining = "X-RateLimit-Remaining"
	HeaderRetryAfter    = "Retry-After"
)

// Cache status values.
const (
	cacheHit    = "hit"
	cacheMiss   = "miss"
	cacheBypass = "bypass"
)

// Health and readiness paths. Exact matches on the raw request path, so a
// request to anything else - including a non-canonical spelling of one of
// these - goes through the pipeline and is judged by the rules.
const (
	HealthPath = "/healthz"
	ReadyPath  = "/readyz"
)

// proxyHandler builds the customer-facing handler.
//
// Deliberately **not** an http.ServeMux, and this is not a style preference.
// ServeMux cleans the request path and answers a non-canonical one with a
// redirect of its own: a request for "/api/v1/../_action/order" never reaches
// a handler, it gets a 307 to "/api/_action/order". That is precisely the
// second interpretation §2 exists to eliminate - the path would be
// canonicalized by net/http's rules rather than by rules.Normalize, pivot
// would never evaluate the request it was actually sent, and a client that
// does not follow redirects would get a 307 where it should have got a
// decision. It also leaks that the path was non-canonical, which is a detail
// about the rule set.
//
// So pivot owns its path handling completely: one handler, two exact-match
// health endpoints, and everything else through the pipeline with the raw path
// intact.
func (s *Server) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Liveness, touching neither Valkey nor the backend, so it answers
		// while the replica is degraded and reports the process itself.
		// Served over plain HTTP too: a probe is not a credentialed request,
		// and failing it for not using TLS would make a healthy replica look
		// dead.
		if r.URL.Path == HealthPath && isRead(r.Method) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte("ok\n"))

			return
		}

		// Readiness is a different question and deliberately not conflated: a
		// replica that cannot reach Valkey is alive and should be restarted,
		// not quietly removed from rotation while its siblings take the load.
		if r.URL.Path == ReadyPath && isRead(r.Method) {
			s.handleReady(w, r)

			return
		}

		s.handle(w, r)
	})
}

// isRead reports whether a method is one the probe endpoints answer.
func isRead(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// handleReady reports whether this replica can serve traffic.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if err := s.state.Store.Ping(ctx); err != nil {
		s.log.Warn("not ready: Valkey is not reachable", "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("valkey unreachable\n"))

		return
	}

	if s.state.Reloader.Table().Global.Empty() {
		// Alive but configured to refuse everything. Reported as not ready so
		// a deployment that forgot to apply a rule set does not quietly send
		// customers 403s.
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("no rule set loaded\n"))

		return
	}

	_, _ = w.Write([]byte("ok\n"))
}

// outcome is what the pipeline decided, for the audit record.
type outcome struct {
	status   int
	client   string
	rule     string
	cache    string
	shared   bool
	upstream bool
}

// handle is §4's pipeline.
//
// The order is the design document's and the ordering is the point: cheap
// rejections come first so that denied, unauthenticated or rate-limited
// traffic never costs a backend call. Each stage either ends the request or
// hands on.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	ctx := r.Context()

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		s.log.Error("could not read settings", "error", err)
		s.fail(w, http.StatusInternalServerError, "unavailable", "pivot is not configured")

		return
	}

	result := outcome{status: http.StatusInternalServerError, cache: cacheBypass}
	defer func() { s.access(r, settings, result, started) }()

	// Stage 1: normalize. A method pivot never forwards is refused here,
	// before any rule set is consulted, which is what makes §10.1's "never" a
	// property of the code rather than of the configuration.
	auth.StripMethodOverride(r)

	if !rules.IsForwardable(r.Method) {
		result.status = http.StatusMethodNotAllowed
		w.Header().Set("Allow", strings.Join(rules.ForwardableMethods, ", "))
		s.fail(w, result.status, "method_not_allowed",
			"pivot forwards only "+strings.Join(rules.ForwardableMethods, ", "))

		return
	}

	path, err := rules.Normalize(r.URL.EscapedPath())
	if err != nil {
		// An ambiguous path is refused rather than guessed at: pivot and the
		// backend's router must see the same request, and a path with two
		// readings has no single answer to forward.
		s.log.Warn("refusing an ambiguous request path",
			"path", sanitise(r.URL.EscapedPath(), 200), "error", err)

		result.status = http.StatusBadRequest
		s.fail(w, result.status, "bad_request", "the request path is not canonical")

		return
	}

	// A plaintext hop is refused. Customers authenticate with a bearer token
	// or Basic credentials on every single request, so a credential on a
	// plaintext hop is a disclosed credential and the client will keep
	// sending it. Unknown is tolerated rather than refused - in proxy mode
	// without a declared trusted set pivot cannot tell, and refusing would
	// break the deployment §10.7 calls expected. The startup log warns about
	// that configuration instead.
	if s.forwarded.Encryption(r) == forwarded.Plaintext {
		s.log.Warn("refusing a plaintext request: credentials travel on every request",
			"path", path)

		result.status = http.StatusUpgradeRequired
		s.fail(w, result.status, "https_required", "pivot accepts requests over HTTPS only")

		return
	}

	// Stage 2: the token endpoint is pivot's own and is never forwarded.
	if settings.FrontendMode == auth.FrontendOAuth2 && path == settings.FrontendPath {
		result.status = s.handleToken(w, r, settings)

		return
	}

	// Stage 3: authenticate.
	client, ok := s.authenticate(ctx, w, r, settings, &result)
	if !ok {
		return
	}

	result.client = client.ID

	// Stage 4: rules.
	decision := s.state.Reloader.Table().For(client.ID).Evaluate(r.Method, path)
	result.rule = decision.Rule

	if !decision.Allowed() {
		s.denied(ctx, w, client, path, decision, &result)

		return
	}

	// Stage 5: rate limit.
	if !s.allow(ctx, w, client, settings, &result) {
		return
	}

	// The body is read once, here: it is needed for the cache key, for
	// coalescing and for the forward leg, and a request body can only be read
	// once.
	body, err := s.readBody(w, r)
	if err != nil {
		result.status = http.StatusRequestEntityTooLarge
		s.fail(w, result.status, "payload_too_large",
			fmt.Sprintf("the request body is larger than %d bytes", MaxRequestBodyBytes))

		return
	}

	s.serve(ctx, w, r, client, settings, path, body, &result)
}

// authenticate resolves the client a request belongs to.
func (s *Server) authenticate(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	settings app.Settings,
	result *outcome,
) (app.Client, bool) {
	credential, err := auth.ExtractCredential(settings.FrontendMode, r)
	if err != nil {
		result.status = http.StatusUnauthorized

		// A missing credential is not an incident - a client misconfigured
		// once produces it - so only a presented-and-wrong credential is
		// counted towards the auth.failed threshold.
		if !errors.Is(err, auth.ErrNoCredential) {
			s.aggregator.AuthFailed(ctx, "unknown", s.sourceFor(r, settings))
		}

		s.unauthorized(w, settings)

		return app.Client{}, false
	}

	var client app.Client

	switch credential.Kind {
	case auth.KindToken:
		token, tokenErr := s.state.Tokens.Resolve(ctx, credential.Token)
		if tokenErr != nil {
			result.status = http.StatusUnauthorized
			s.aggregator.AuthFailed(ctx, "token", s.sourceFor(r, settings))
			s.unauthorized(w, settings)

			return app.Client{}, false
		}

		client, err = s.state.Clients.Get(ctx, token.ClientID)
		if err == nil && client.Disabled {
			err = app.ErrClientDisabled
		}

	case auth.KindClientSecret:
		client, err = s.state.Clients.Authenticate(ctx, credential.ClientID, credential.Secret)
	}

	if err != nil {
		result.status = http.StatusUnauthorized

		subject := credential.ClientID
		if subject == "" {
			subject = "token"
		}

		// The reason goes to the log rather than to the stored trail: one
		// record per failed request would be the volume §10.8's split exists
		// to avoid, and the aggregator writes the durable record once the
		// failures look like an incident rather than a typo.
		s.log.Warn("authentication failed",
			"subject", subject,
			"reason", authFailureReason(err),
			"source", s.sourceFor(r, settings))
		s.aggregator.AuthFailed(ctx, subject, s.sourceFor(r, settings))
		s.unauthorized(w, settings)

		return app.Client{}, false
	}

	return client, true
}

// authFailureReason renders why authentication failed, for the audit record
// only - the response says the same thing either way.
func authFailureReason(err error) string {
	switch {
	case errors.Is(err, app.ErrClientDisabled):
		return "client disabled"
	case errors.Is(err, app.ErrTokenNotFound):
		return "token unknown or expired"
	default:
		return "unknown client or wrong secret"
	}
}

// denied ends a request the rules refused.
func (s *Server) denied(
	ctx context.Context,
	w http.ResponseWriter,
	client app.Client,
	path string,
	decision rules.Decision,
	result *outcome,
) {
	result.status = http.StatusForbidden

	// The denial is in the access log with its rule and outcome, every time.
	// The stored record is the aggregate, written by the aggregator once the
	// denials pass a threshold - a client retrying a denied path in a loop
	// must not write a ninety-day record per attempt.
	s.aggregator.Denied(ctx, client.ID, path, decision.Rule)

	// The response says the request is not permitted and nothing about why.
	// Which rule denied it, and whether any rule matched at all, is
	// information about the policy - and a customer enumerating paths against
	// the error text would be mapping the rule set.
	s.fail(w, result.status, "forbidden", "this request is not permitted")
}

// allow applies the client's rate limit.
func (s *Server) allow(
	ctx context.Context,
	w http.ResponseWriter,
	client app.Client,
	settings app.Settings,
	result *outcome,
) bool {
	limit := client.RateLimit
	if limit.Unlimited() {
		limit = settings.DefaultRateLimit
	}

	decision, err := s.state.Limiter.Allow(ctx, client.ID, limit)
	if err != nil {
		// A limiter that cannot reach Valkey fails open. That is the
		// uncomfortable direction and it is the right one here: the
		// alternative is that a Valkey hiccup takes every customer offline,
		// and the backend still has its own concurrency limit and its own
		// permissions. The log line is what makes the window visible.
		s.log.Error("could not apply the rate limit; allowing the request",
			"client", client.ID, "error", err)

		return true
	}

	if decision.Allowed {
		w.Header().Set(HeaderRateRemaining, strconv.Itoa(decision.Remaining))

		return true
	}

	result.status = http.StatusTooManyRequests

	s.aggregator.RateLimited(ctx, client.ID)

	w.Header().Set(HeaderRateRemaining, "0")
	w.Header().Set(HeaderRetryAfter, strconv.Itoa(int(decision.RetryAfter.Seconds())))
	s.fail(w, result.status, "rate_limited", "the client's rate limit has been exceeded")

	return false
}

// readBody reads a request body, bounded.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	limited := http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)

	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// unauthorized writes the 401, in the shape the configured frontend mode
// implies.
//
// In oauth2 mode that is RFC 6749's error body, because a client written
// against the backend's token endpoint will parse it. The description is the
// same whether the client was unknown, the secret wrong or the token expired:
// distinguishing them tells an attacker which half of a guess was right.
func (s *Server) unauthorized(w http.ResponseWriter, settings app.Settings) {
	if settings.FrontendMode == auth.FrontendOAuth2 {
		auth.WriteError(w, http.StatusUnauthorized, auth.InvalidClient())

		return
	}

	w.Header().Set("WWW-Authenticate", `Basic realm="pivot"`)
	s.fail(w, http.StatusUnauthorized, "unauthorized", "the credentials are invalid")
}

// fail writes one of pivot's own error responses.
//
// JSON, because every backend pivot is designed to front speaks it and a
// client that got HTML where it expected JSON would report a confusing error.
// The body deliberately carries no detail about the policy: these responses
// are the ones a customer can enumerate against.
func (s *Server) fail(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": message,
	})
}

// sourceFor resolves the client address for a log or audit record, reduced by
// the configured mode.
func (s *Server) sourceFor(r *http.Request, settings app.Settings) string {
	source, err := s.forwarded.Source(r)
	if err != nil {
		return ""
	}

	return app.RecordAddress(settings.AccessLogAddress, source)
}

// access writes the per-request audit log line (§9.2).
//
// To the structured log rather than to Valkey: this is one record per request,
// so the operator's log pipeline owns the volume and the retention. §10.8
// records the split and why pivot cannot promise a retention period for
// records that leave the process.
//
// Every field a client controls is bounded and stripped of control characters,
// because a log line a client can inject a newline into is a log line a client
// can forge.
func (s *Server) access(r *http.Request, settings app.Settings, result outcome, started time.Time) {
	attrs := []any{
		"method", r.Method,
		"path", sanitise(r.URL.EscapedPath(), 512),
		"status", result.status,
		"duration", time.Since(started).Round(time.Microsecond).String(),
		"cache", result.cache,
	}

	if result.client != "" {
		attrs = append(attrs, "client", result.client)
	}

	if result.rule != "" {
		attrs = append(attrs, "rule", result.rule)
	}

	if result.shared {
		attrs = append(attrs, "coalesced", true)
	}

	if result.upstream {
		attrs = append(attrs, "upstream", true)
	}

	if source := s.sourceFor(r, settings); source != "" {
		attrs = append(attrs, "source", source)
	}

	if agent := r.UserAgent(); agent != "" {
		attrs = append(attrs, "user_agent", sanitise(agent, 200))
	}

	s.log.Info("request", attrs...)
}

// sanitise strips control characters from a client-supplied string and bounds
// its length.
func sanitise(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}

		return r
	}, value)

	if limit > 0 && len(value) > limit {
		value = value[:limit]
	}

	return value
}

// cacheKeyFor builds the cache key for a request, or reports that the route is
// not cacheable.
func (s *Server) cacheKeyFor(
	client app.Client, set *rules.Set, method, path, query string, body []byte,
) (cache.Key, rules.Cache, bool) {
	config, ok := set.CacheFor(method, path)
	if !ok {
		return cache.Key{}, rules.Cache{}, false
	}

	key, err := cache.NewKey(client.ID, method, path, query, body, !config.Shared)
	if err != nil {
		// A body too large to key on is not cached rather than keyed on a
		// truncation, which would make two different requests share an entry.
		return cache.Key{}, rules.Cache{}, false
	}

	return key, config, true
}
