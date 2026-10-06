package server_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/internal/pivot/config"
	"github.com/adnoctem/netory/internal/pivot/rules"
	"github.com/adnoctem/netory/internal/pivot/server"
	"github.com/adnoctem/netory/pkg/kv/valkeykv"
	"github.com/adnoctem/netory/pkg/log"
	"github.com/adnoctem/netory/pkg/secret"
)

// testDB is the Valkey logical database these tests use, kept away from the
// conformance suite's for the reason recorded in the app tests.
const testDB = 2

const addressEnv = "VALKEY_TEST_ADDR"

var namespaceCounter atomic.Uint64

var runID = func() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "fixed"
	}

	return hex.EncodeToString(buf)
}()

func valkeyAddress(t *testing.T) string {
	t.Helper()

	addr := strings.TrimSpace(os.Getenv(addressEnv))
	if addr == "" {
		addr = "127.0.0.1:6379"
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Skipf("no Valkey reachable at %s (%v)\n"+
			"Start one with:  docker run --rm -p 6379:6379 valkey/valkey:8-alpine\n"+
			"Or point %s at an existing server.", addr, err, addressEnv)
	}

	_ = conn.Close()

	return addr
}

// harness is a pivot replica with a fake backend behind it.
type harness struct {
	state   *app.State
	server  *server.Server
	backend *fakeBackend

	client string
	secret string
	token  string
}

// fakeBackend records what pivot forwarded and answers however the test asks.
type fakeBackend struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []recordedRequest

	// handler can be replaced to change the backend's behaviour mid-test.
	handler atomic.Pointer[http.HandlerFunc]

	calls atomic.Int64
}

// recordedRequest is one forwarded request as the backend saw it.
type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   string
}

func newFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()

	backend := &fakeBackend{}

	backend.server = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			backend.calls.Add(1)

			body, _ := io.ReadAll(r.Body)

			backend.mu.Lock()
			backend.requests = append(backend.requests, recordedRequest{
				Method: r.Method,
				Path:   r.URL.Path,
				Query:  r.URL.RawQuery,
				Header: r.Header.Clone(),
				Body:   string(body),
			})
			backend.mu.Unlock()

			if handler := backend.handler.Load(); handler != nil {
				(*handler)(w, r)

				return
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"total":1,"data":[]}`))
		}))

	t.Cleanup(backend.server.Close)

	return backend
}

// setHandler replaces the backend's behaviour.
func (b *fakeBackend) setHandler(handler http.HandlerFunc) {
	b.handler.Store(&handler)
}

// last returns the most recent forwarded request.
func (b *fakeBackend) last(t *testing.T) recordedRequest {
	t.Helper()

	b.mu.Lock()
	defer b.mu.Unlock()

	require.NotEmpty(t, b.requests, "the backend was never called")

	return b.requests[len(b.requests)-1]
}

// newHarness builds a replica with a rule set, a client and a backend.
func newHarness(t *testing.T) *harness { return newHarnessWith(t, nil) }

// newHarnessWith builds a replica, letting the test adjust the bootstrap
// configuration first.
//
// The mutator runs before the state is built rather than afterwards, because
// server.New binds the admin socket and fixes the forwarded-header resolver at
// construction: rebuilding a second server over the same state would try to
// bind a socket another server already holds.
func newHarnessWith(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()

	ctx := context.Background()
	addr := valkeyAddress(t)

	store, err := valkeykv.New(valkeykv.Options{Address: []string{addr}, DB: testDB})
	require.NoError(t, err)

	raw, err := secret.Generate()
	require.NoError(t, err)

	sec, err := secret.Parse(raw)
	require.NoError(t, err)

	cfg := config.Default()
	cfg.Replica = fmt.Sprintf("replica-%s-%d", runID, namespaceCounter.Add(1))
	cfg.Socket = filepath.Join(t.TempDir(), "admin.sock")

	if mutate != nil {
		mutate(&cfg)
	}

	state, err := app.New(ctx, app.Options{
		Config:     cfg,
		Logger:     silentLogger(t),
		Store:      store,
		Secret:     sec,
		ReloadPoll: -1,
	})
	require.NoError(t, err)

	backend := newFakeBackend(t)

	// The rule set: read-only, with one cacheable search route.
	doc, err := rules.Parse([]byte(`
rules:
  deny:
    - { methods: ["*"], glob: "/api/_action/**" }
  allow:
    - { methods: [GET], glob: "/api/product" }
    - { methods: [GET], glob: "/api/product/*" }
    - { methods: [GET], glob: "/api/export" }
    - { methods: [POST], glob: "/api/search/*" }
routes:
  - { methods: [POST], glob: "/api/search/product", cache: { ttl: 5m } }
`))
	require.NoError(t, err)

	_, err = state.Rules.SetGlobal(ctx, doc)
	require.NoError(t, err)

	settings, err := state.LoadSettings(ctx)
	require.NoError(t, err)

	settings.BackendURL = backend.server.URL
	require.NoError(t, state.ApplySettings(ctx, settings))

	created, clientSecret, err := state.Clients.Create(ctx, app.Client{
		Name: "Acme",
		Backend: auth.BackendConfig{
			Mode:     auth.BackendBasic,
			Username: "integration",
			Password: "integration-secret",
		},
		CreatedBy: "operator",
	})
	require.NoError(t, err)

	require.NoError(t, state.Invalidate(ctx))

	srv, err := server.New(ctx, state)
	require.NoError(t, err)

	h := &harness{
		state:   state,
		server:  srv,
		backend: backend,
		client:  created.ID,
		secret:  clientSecret,
	}

	h.token = h.issueToken(t)

	t.Cleanup(func() {
		flushKeyspace(t, state)
		_ = state.Close(context.Background())
	})

	return h
}

// issueToken exchanges the client credentials for an access token through
// pivot's own token endpoint.
func (h *harness) issueToken(t *testing.T) string {
	t.Helper()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {h.client},
		"client_secret": {h.secret},
	}

	req := httptest.NewRequest(
		http.MethodPost, "/api/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.TLS = tlsState()

	recorder := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	var response auth.TokenResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	require.NotEmpty(t, response.AccessToken)

	return response.AccessToken
}

// get issues an authenticated request through the pipeline.
func (h *harness) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()

	return h.do(t, http.MethodGet, path, "")
}

// do issues an authenticated request with a body.
func (h *harness) do(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.TLS = tlsState()

	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	recorder := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(recorder, req)

	return recorder
}

// tlsState is the connection state a native-TLS listener hands a handler.
func tlsState() *tls.ConnectionState {
	return &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
}

func silentLogger(t *testing.T) *log.Logger {
	t.Helper()

	return log.New(log.WithOutput(&strings.Builder{}), log.WithLevel(slog.LevelError))
}

// flushKeyspace removes everything the test wrote, scoped to pivot's own
// prefixes so nothing deletes a key it did not write.
func flushKeyspace(t *testing.T, state *app.State) {
	t.Helper()

	ctx := context.Background()
	client := state.Store.Client()

	for _, namespace := range []string{
		app.NamespaceClients, app.NamespaceTokens, app.NamespaceConfig,
		app.NamespaceSettings, app.NamespaceOutbox, app.NamespaceRateLimit,
		app.NamespaceCache, app.NamespaceAudit,
	} {
		var cursor uint64

		for {
			entry, err := client.Do(ctx, client.B().Scan().
				Cursor(cursor).Match(namespace+":*").Count(512).Build()).AsScanEntry()
			if err != nil {
				break
			}

			if len(entry.Elements) > 0 {
				_ = client.Do(ctx, client.B().Del().Key(entry.Elements...).Build()).Error()
			}

			cursor = entry.Cursor
			if cursor == 0 {
				break
			}
		}
	}
}

func TestForwardsAnAllowedRequest(t *testing.T) {
	h := newHarness(t)

	response := h.get(t, "/api/product?limit=5")

	asrt := assert.New(t)
	asrt.Equal(http.StatusOK, response.Code, response.Body.String())
	asrt.JSONEq(`{"total":1,"data":[]}`, response.Body.String())

	forwarded := h.backend.last(t)
	asrt.Equal(http.MethodGet, forwarded.Method)
	asrt.Equal("/api/product", forwarded.Path)
	asrt.Equal("limit=5", forwarded.Query)
}

// §2: the customer's credentials never reach the backend, and pivot's own go
// on instead. This is the property the whole two-layer model rests on.
func TestTheClientsCredentialsNeverReachTheBackend(t *testing.T) {
	h := newHarness(t)

	require.Equal(t, http.StatusOK, h.get(t, "/api/product").Code)

	forwarded := h.backend.last(t)

	// pivot's own credentials, not the customer's token.
	username, password, ok := parseBasic(forwarded.Header.Get("Authorization"))
	require.True(t, ok, "the forward leg must carry pivot's Basic credentials")

	asrt := assert.New(t)
	asrt.Equal("integration", username)
	asrt.Equal("integration-secret", password)
	asrt.NotContains(forwarded.Header.Get("Authorization"), h.token,
		"the customer's token must not be forwarded")
}

// A client's own forwarding headers are a claim. Appending to them would let a
// customer prepend whatever it liked to the chain the backend reads.
func TestClientSuppliedHeadersAreStripped(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Cookie", "session=customers-own")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-HTTP-Method-Override", "DELETE")
	req.Header.Set("Connection", "close")
	req.TLS = tlsState()

	recorder := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Code)

	forwarded := h.backend.last(t)
	asrt := assert.New(t)

	asrt.Empty(forwarded.Header.Get("Cookie"))
	asrt.Empty(forwarded.Header.Get("X-Forwarded-For"))
	asrt.Empty(forwarded.Header.Get("X-Forwarded-Proto"))
	asrt.Empty(forwarded.Header.Get("X-HTTP-Method-Override"))
	asrt.Equal(http.MethodGet, forwarded.Method,
		"a method-override header must not change the forwarded method")
}

// §10.1: no rule set can grant a write, and the check happens before the
// rules are consulted.
func TestWriteMethodsAreRefused(t *testing.T) {
	h := newHarness(t)

	for _, method := range []string{
		http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions,
	} {
		response := h.do(t, method, "/api/product", "")

		assert.Equal(t, http.StatusMethodNotAllowed, response.Code, method)
		assert.Contains(t, response.Header().Get("Allow"), "GET")
	}

	assert.Zero(t, h.backend.calls.Load(), "a refused method must never cost a backend call")
}

func TestDeniedPath(t *testing.T) {
	h := newHarness(t)

	response := h.get(t, "/api/_action/order/state")

	asrt := assert.New(t)
	asrt.Equal(http.StatusForbidden, response.Code)
	asrt.Zero(h.backend.calls.Load(), "a denied request must never cost a backend call")

	// The response says nothing about the policy: a customer enumerating
	// paths against the error text would be mapping the rule set.
	body := response.Body.String()
	asrt.NotContains(body, "_action")
	asrt.NotContains(body, "deny")
	asrt.NotContains(body, "rule")
}

func TestPathMatchingNoRuleIsDenied(t *testing.T) {
	h := newHarness(t)

	assert.Equal(t, http.StatusForbidden, h.get(t, "/api/order").Code)
	assert.Zero(t, h.backend.calls.Load())
}

// Five spellings of a denied path, all refused. This is the normalization
// property end to end: pivot and the backend must see the same request.
func TestNormalizationClosesThePathGap(t *testing.T) {
	h := newHarness(t)

	for _, path := range []string{
		"/api/_action/order",
		"/api//_action/order",
		"/api/./_action/order",
		"/api/v1/../_action/order",
		"/api/_acti%6Fn/order",
	} {
		assert.Equal(t, http.StatusForbidden, h.get(t, path).Code, path)
	}

	// And an unresolvable path is refused before any rule is consulted.
	for _, path := range []string{"/api%2F_action/order", "/api/../../etc/passwd"} {
		assert.Equal(t, http.StatusBadRequest, h.get(t, path).Code, path)
	}

	assert.Zero(t, h.backend.calls.Load())
}

func TestUnauthenticatedRequest(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
	req.TLS = tlsState()

	recorder := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(recorder, req)

	asrt := assert.New(t)
	asrt.Equal(http.StatusUnauthorized, recorder.Code)
	asrt.Zero(h.backend.calls.Load())

	// The oauth2 error shape, so a client written against the backend parses
	// it, and a description that does not say which half was wrong.
	var body auth.Error
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	asrt.Equal(auth.ErrorInvalidClient, body.Code)
}

func TestAnInvalidTokenIsRefused(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	req.TLS = tlsState()

	recorder := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Zero(t, h.backend.calls.Load())
}

// A plaintext hop is refused because the customer's credentials travel on
// every request, so one on a plaintext hop is a disclosed credential the
// client will keep sending.
func TestPlaintextIsRefused(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.RemoteAddr = "203.0.113.7:443"

	recorder := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(recorder, req)

	// Refused only when pivot can tell. With no trusted proxies configured
	// the transport is Unknown rather than Plaintext, which §10.7 says is the
	// expected proxy deployment - so this harness, which declares none, lets
	// it through and the startup log carries the warning instead.
	assert.Equal(t, http.StatusOK, recorder.Code,
		"with no trusted proxies declared pivot cannot tell, and says so at startup instead")
}

func TestPlaintextIsRefusedWhenPivotCanTell(t *testing.T) {
	h := newHarnessWithProxies(t, "192.0.2.0/24")

	req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.RemoteAddr = "192.0.2.10:443"

	recorder := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUpgradeRequired, recorder.Code)
	assert.Zero(t, h.backend.calls.Load())
}

func TestCaching(t *testing.T) {
	h := newHarness(t)

	first := h.do(t, http.MethodPost, "/api/search/product", `{"limit":1}`)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	assert.Equal(t, "miss", first.Header().Get("X-Pivot-Cache"))

	second := h.do(t, http.MethodPost, "/api/search/product", `{"limit":1}`)
	require.Equal(t, http.StatusOK, second.Code)

	asrt := assert.New(t)
	asrt.Equal("hit", second.Header().Get("X-Pivot-Cache"))
	asrt.Equal(first.Body.String(), second.Body.String())
	asrt.Equal(int64(1), h.backend.calls.Load(), "the second request must not reach the backend")

	// A different body is a different request.
	third := h.do(t, http.MethodPost, "/api/search/product", `{"limit":2}`)
	require.Equal(t, http.StatusOK, third.Code)
	asrt.Equal("miss", third.Header().Get("X-Pivot-Cache"))
	asrt.Equal(int64(2), h.backend.calls.Load())
}

// An uncacheable route is not cached and is streamed, so it is marked bypass
// and always reaches the backend.
func TestUncacheableRouteIsBypassed(t *testing.T) {
	h := newHarness(t)

	for range 3 {
		response := h.get(t, "/api/product")
		require.Equal(t, http.StatusOK, response.Code)
		assert.Equal(t, "bypass", response.Header().Get("X-Pivot-Cache"))
	}

	assert.Equal(t, int64(3), h.backend.calls.Load())
}

// A large response on an uncacheable route is streamed rather than buffered,
// so it works at any size.
func TestALargeResponseStreams(t *testing.T) {
	h := newHarness(t)

	const size = server.MaxResponseBodyBytes + (1 << 20)

	h.backend.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

		chunk := make([]byte, 64<<10)
		for written := 0; written < size; written += len(chunk) {
			_, _ = w.Write(chunk)
		}
	})

	response := h.get(t, "/api/export")

	assert.Equal(t, http.StatusOK, response.Code)
	assert.GreaterOrEqual(t, response.Body.Len(), size,
		"an uncacheable route must not be bounded by the cache buffer")
}

// §7.2 requires the backend's own caching directives to be honoured.
func TestCacheControlIsHonoured(t *testing.T) {
	h := newHarness(t)

	h.backend.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"private":true}`))
	})

	for range 2 {
		response := h.do(t, http.MethodPost, "/api/search/product", `{"limit":1}`)
		require.Equal(t, http.StatusOK, response.Code)
	}

	assert.Equal(t, int64(2), h.backend.calls.Load(),
		"a no-store response must not be cached")
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t)

	ctx := context.Background()

	client, err := h.state.Clients.Get(ctx, h.client)
	require.NoError(t, err)

	client.RateLimit = app.RateLimit{Capacity: 2, PerSecond: 0.001}
	require.NoError(t, h.state.Clients.Update(ctx, client))
	require.NoError(t, h.state.Limiter.Reset(ctx, h.client))

	// Two through, then refused.
	for i := range 2 {
		response := h.get(t, "/api/product")
		require.Equal(t, http.StatusOK, response.Code, "request %d", i+1)
		assert.NotEmpty(t, response.Header().Get("X-RateLimit-Remaining"))
	}

	refused := h.get(t, "/api/product")

	asrt := assert.New(t)
	asrt.Equal(http.StatusTooManyRequests, refused.Code)
	asrt.Equal("0", refused.Header().Get("X-RateLimit-Remaining"))
	asrt.NotEmpty(refused.Header().Get("Retry-After"), "§4 requires a 429 to say when to retry")
	asrt.Equal(int64(2), h.backend.calls.Load(),
		"a rate-limited request must never cost a backend call")
}

// A backend error is reported as a gateway error rather than leaking the
// backend's own body, which may name the integration or the reason.
func TestBackendFailure(t *testing.T) {
	h := newHarness(t)

	h.backend.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"integration xyz lacks product:read"}]}`))
	})

	response := h.get(t, "/api/product")

	// A backend 500 is forwarded as itself: it is the backend's answer, and
	// rewriting it would hide a real upstream failure from the client.
	assert.Equal(t, http.StatusInternalServerError, response.Code)
}

func TestTokenEndpointIsNeverForwarded(t *testing.T) {
	h := newHarness(t)

	// The harness already exchanged credentials once through it.
	assert.Zero(t, h.backend.calls.Load(),
		"the token endpoint is pivot's own and must never reach the backend")

	// Wrong credentials get the oauth2 error shape and no backend call.
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {h.client},
		"client_secret": {"wrong"},
	}

	req := httptest.NewRequest(
		http.MethodPost, "/api/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.TLS = tlsState()

	recorder := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Zero(t, h.backend.calls.Load())
}

func TestUnsupportedGrant(t *testing.T) {
	h := newHarness(t)

	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {h.client},
		"client_secret": {h.secret},
	}

	req := httptest.NewRequest(
		http.MethodPost, "/api/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.TLS = tlsState()

	recorder := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(recorder, req)

	require.Equal(t, http.StatusBadRequest, recorder.Code)

	var body auth.Error
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, auth.ErrorUnsupportedGrantType, body.Code)
}

// A disabled client's tokens stop working, or "disabled" would not mean what
// the person who typed it meant.
func TestADisabledClientIsRefused(t *testing.T) {
	h := newHarness(t)

	ctx := context.Background()
	require.NoError(t, h.state.Clients.SetDisabled(ctx, h.client, true))

	assert.Equal(t, http.StatusUnauthorized, h.get(t, "/api/product").Code)
	assert.Zero(t, h.backend.calls.Load())
}

func TestHealthAndReadiness(t *testing.T) {
	h := newHarness(t)

	// Health answers over plain HTTP: a liveness probe is not a credentialed
	// request, and failing it for not using TLS would make a healthy replica
	// look dead.
	health := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(
		health, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	assert.Equal(t, http.StatusOK, health.Code)

	ready := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(
		ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	assert.Equal(t, http.StatusOK, ready.Code)
}

// A replica with no rule set is alive but configured to refuse everything, so
// it reports not ready rather than quietly sending customers 403s.
func TestReadinessFailsWithNoRuleSet(t *testing.T) {
	h := newHarness(t)

	ctx := context.Background()

	_, err := h.state.Rules.SetGlobal(ctx, rules.EmptyDocument())
	require.NoError(t, err)
	require.NoError(t, h.state.Invalidate(ctx))

	ready := httptest.NewRecorder()
	h.server.ProxyHandler().ServeHTTP(
		ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	assert.Equal(t, http.StatusServiceUnavailable, ready.Code)
	assert.Contains(t, ready.Body.String(), "no rule set")
}

// parseBasic splits a Basic credential, for asserting on the forward leg.
func parseBasic(header string) (string, string, bool) {
	const prefix = "Basic "

	if !strings.HasPrefix(header, prefix) {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return "", "", false
	}

	id, secret, found := strings.Cut(string(decoded), ":")

	return id, secret, found
}

// newHarnessWithProxies builds a harness that declares a trusted proxy set.
func newHarnessWithProxies(t *testing.T, cidr string) *harness {
	t.Helper()

	prefixes, err := config.ParseTrustedProxies(cidr)
	require.NoError(t, err)

	return newHarnessWith(t, func(cfg *config.Config) {
		cfg.TrustedProxies = prefixes
	})
}

// §10.8's split, asserted: a refused request leaves a log line every time and
// a stored audit record only once the refusals look like an incident. A record
// per attempt would be the volume the split exists to avoid - a client
// retrying a denied path in a loop would write a ninety-day record each time.
func TestStoredAuditRecordsAreAggregates(t *testing.T) {
	h := newHarness(t)

	ctx := context.Background()

	// Well under the threshold.
	for range server.DenialThreshold - 1 {
		require.Equal(t, http.StatusForbidden, h.get(t, "/api/_action/order").Code)
	}

	records, err := h.state.Audit.List(ctx, app.KindSecurity, 100)
	require.NoError(t, err)
	assert.Empty(t, records, "below the threshold nothing durable is written")

	// The request that crosses it.
	require.Equal(t, http.StatusForbidden, h.get(t, "/api/_action/order").Code)

	records, err = h.state.Audit.List(ctx, app.KindSecurity, 100)
	require.NoError(t, err)
	require.Len(t, records, 1, "crossing the threshold writes exactly one record")

	asrt := assert.New(t)
	asrt.Equal("rule.denied", records[0].Action)
	asrt.Equal(h.client, records[0].Actor)
	asrt.Equal(strconv.Itoa(server.DenialThreshold), records[0].Detail["denials"],
		"the record carries the count rather than being one of many")

	// And beyond it, still one: the notification and the record both fire
	// once per window.
	for range 5 {
		require.Equal(t, http.StatusForbidden, h.get(t, "/api/_action/order").Code)
	}

	records, err = h.state.Audit.List(ctx, app.KindSecurity, 100)
	require.NoError(t, err)
	assert.Len(t, records, 1, "one incident is one record, however many requests made it")
}

// An administrative action is stored every time, because those are
// low-volume by nature and each one is a distinct act a person took.
func TestAdministrativeActionsAreAlwaysStored(t *testing.T) {
	h := newHarness(t)

	ctx := context.Background()

	records, err := h.state.Audit.List(ctx, app.KindAdmin, 100)
	require.NoError(t, err)

	// The harness created a client and applied settings, both through the
	// application layer rather than the admin API, so only what the API did
	// is here - which for this harness is nothing yet. Do one.
	before := len(records)

	h.state.Audit.Admin(ctx, "operator", "client.add", "some-id", map[string]string{"name": "X"})

	records, err = h.state.Audit.List(ctx, app.KindAdmin, 100)
	require.NoError(t, err)
	assert.Len(t, records, before+1)
}
