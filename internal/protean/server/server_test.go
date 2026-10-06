package server_test

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/internal/protean/config"
	"github.com/adnoctem/netory/internal/protean/provider"
	"github.com/adnoctem/netory/internal/protean/server"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
	"github.com/adnoctem/netory/pkg/log"
	"github.com/adnoctem/netory/pkg/secret"
)

// fakeProvider records what protean asked it to write.
//
// Registered into the real registry, so the update path runs through
// provider.New exactly as it does in production - only the far end is fake.
type fakeProvider struct {
	name string
	zone string

	mu       sync.Mutex
	upserted []provider.Record
	failWith error
}

var (
	fakesMu sync.Mutex
	fakes   = map[string]*fakeProvider{}
)

const kindFake = "fake"

func init() {
	provider.Register(kindFake, func(cfg provider.Config) (provider.Provider, error) {
		fakesMu.Lock()
		defer fakesMu.Unlock()

		// One instance per configured name, shared between the registry and
		// the test, so a test can inspect what the update path wrote.
		if existing, ok := fakes[cfg.Name]; ok {
			return existing, nil
		}

		p := &fakeProvider{name: cfg.Name, zone: cfg.Zone}
		fakes[cfg.Name] = p

		return p, nil
	})
}

func fakeFor(name string) *fakeProvider {
	fakesMu.Lock()
	defer fakesMu.Unlock()

	return fakes[name]
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Kind() string { return kindFake }

func (f *fakeProvider) Get(context.Context, string, string) ([]provider.Record, error) {
	return nil, nil
}

func (f *fakeProvider) Upsert(_ context.Context, _ string, records []provider.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.failWith != nil {
		return f.failWith
	}

	f.upserted = append(f.upserted, records...)

	return nil
}

func (f *fakeProvider) Delete(context.Context, string, []provider.Record) error { return nil }

func (f *fakeProvider) Redacted() map[string]string { return map[string]string{"zone": f.zone} }

func (f *fakeProvider) Verify(context.Context, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.failWith
}

func (f *fakeProvider) records() []provider.Record {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]provider.Record(nil), f.upserted...)
}

func (f *fakeProvider) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.upserted, f.failWith = nil, nil
}

func (f *fakeProvider) setFailure(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.failWith = err
}

// harness is a protean server wired over an in-memory store.
type harness struct {
	state  *app.State
	update http.Handler
	admin  http.Handler
	token  string
	host   string
	fake   *fakeProvider
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()

	ctx := context.Background()

	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.Socket = "/tmp/unused.sock"
	cfg.Database = ""
	if mutate != nil {
		mutate(&cfg)
	}

	logger := log.New(log.WithOutput(&strings.Builder{}), log.WithLevel(slog.LevelError))

	// The store is opened directly rather than through app.Open, which would
	// read PROTEAN_SECRET from the environment and create a directory.
	store, err := badgerkv.New(badgerkv.Options{InMemory: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	raw, err := secret.Generate()
	require.NoError(t, err)

	sec, err := secret.Parse(raw)
	require.NoError(t, err)

	// Delivery is left off so nothing races a test asserting on the outbox,
	// and deduplication is disabled so two distinct failures each produce an
	// event without the test having to reason about the window.
	state, err := app.New(ctx, app.Options{
		Config:      cfg,
		Logger:      logger,
		Store:       store,
		Secret:      sec,
		DedupWindow: -1,
	})
	require.NoError(t, err)

	providerName := "fake-main"
	require.NoError(t, state.Providers.Add(ctx, provider.Config{
		Name: providerName,
		Kind: kindFake,
		Zone: "example.org",
	}))

	host := "dyn.example.org"
	require.NoError(t, state.Hosts.Add(ctx, app.Host{
		Name: host, Provider: providerName, ManageA: true, ManageAAAA: true,
	}))

	token, _, err := state.Tokens.Create(ctx, host, "test")
	require.NoError(t, err)

	updateHandler, err := server.UpdateHandlerForTest(state)
	require.NoError(t, err)

	adminHandler, err := server.AdminHandlerForTest(state)
	require.NoError(t, err)

	fake := fakeFor(providerName)
	require.NotNil(t, fake)
	fake.reset()

	return &harness{
		state:  state,
		update: updateHandler,
		admin:  adminHandler,
		token:  token,
		host:   host,
		fake:   fake,
	}
}

// do issues an update request and returns the status and the DynDNS2 token.
func (h *harness) do(t *testing.T, query string, opts ...func(*http.Request)) (int, string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, server.UpdatePath+query, nil)
	req.SetBasicAuth(h.host, h.token)

	// Native TLS by default, so the plaintext refusal does not fire in tests
	// that are about something else.
	req.TLS = &tlsState

	for _, opt := range opts {
		opt(req)
	}

	rec := httptest.NewRecorder()
	h.update.ServeHTTP(rec, req)

	return rec.Code, strings.TrimSpace(rec.Body.String())
}

// tlsState marks a request as having arrived over TLS, which the update
// endpoint requires: HTTP Basic sends the token on every request.
var tlsState = tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}

// The common case: a client sends an address protean has not seen, it is
// written to the provider, and the response is `good`.
func TestUpdateGood(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	status, body := h.do(t, "?myip=203.0.113.1")
	asrt.Equal(http.StatusOK, status)
	asrt.Equal("good 203.0.113.1", body)

	records := h.fake.records()
	require.Len(t, records, 1)
	asrt.Equal("dyn", records[0].Name, "the name must be relative to the provider's zone")
	asrt.Equal(provider.TypeA, records[0].Type)
	asrt.Equal("203.0.113.1", records[0].Value)

	// The address is recorded, which is what makes the next identical update
	// free.
	host, err := h.state.Hosts.Get(context.Background(), h.host)
	asrt.NoError(err)
	asrt.Equal("203.0.113.1", host.LastIPv4)
	asrt.False(host.LastUpdateAt.IsZero())
}

// An unchanged address must cost no provider call. A router re-sending the
// same address every five minutes is the normal case, not the exception.
func TestUpdateNoChangeCostsNoProviderCall(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	status, body := h.do(t, "?myip=203.0.113.1")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "good 203.0.113.1", body)
	require.Len(t, h.fake.records(), 1)

	// Three more identical updates.
	for range 3 {
		status, body = h.do(t, "?myip=203.0.113.1")
		asrt.Equal(http.StatusOK, status)
		asrt.Equal("nochg 203.0.113.1", body)
	}

	asrt.Len(h.fake.records(), 1, "an unchanged address must not reach the provider again")

	// A changed address does go through.
	status, body = h.do(t, "?myip=203.0.113.2")
	asrt.Equal(http.StatusOK, status)
	asrt.Equal("good 203.0.113.2", body)
	asrt.Len(h.fake.records(), 2)
}

// Section 6.3: AAAA records are updated independently of A, which is what
// makes protean usable on DS-Lite.
func TestUpdateFamiliesAreIndependent(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	status, body := h.do(t, "?myip=203.0.113.1&myipv6=2001:db8::1")
	asrt.Equal(http.StatusOK, status)
	asrt.Contains(body, "good")
	asrt.Contains(body, "203.0.113.1")
	asrt.Contains(body, "2001:db8::1")

	records := h.fake.records()
	require.Len(t, records, 2)

	byType := map[string]string{}
	for _, record := range records {
		byType[record.Type] = record.Value
	}
	asrt.Equal("203.0.113.1", byType[provider.TypeA])
	asrt.Equal("2001:db8::1", byType[provider.TypeAAAA])

	// Changing only IPv6 writes only the AAAA record.
	h.fake.reset()
	status, body = h.do(t, "?myip=203.0.113.1&myipv6=2001:db8::2")
	asrt.Equal(http.StatusOK, status)
	asrt.Contains(body, "good")

	records = h.fake.records()
	require.Len(t, records, 1, "only the changed family may be written")
	asrt.Equal(provider.TypeAAAA, records[0].Type)
	asrt.Equal("2001:db8::2", records[0].Value)
}

// myip may carry an IPv6 address - some clients send one - so the family is
// decided by what the value parses as, not by the parameter's name.
func TestUpdateDispatchesByAddressFamilyNotParameterName(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	status, _ := h.do(t, "?myip=2001:db8::5")
	asrt.Equal(http.StatusOK, status)

	records := h.fake.records()
	require.Len(t, records, 1)
	asrt.Equal(provider.TypeAAAA, records[0].Type, "an IPv6 value in myip must become an AAAA record")
}

// ddclient sends "v4,v6" in myip when configured for both families.
func TestUpdateAcceptsACommaSeparatedPair(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	status, _ := h.do(t, "?myip=203.0.113.1,2001:db8::1")
	asrt.Equal(http.StatusOK, status)
	asrt.Len(h.fake.records(), 2)
}

// With no explicit address, the request's source is used - which is what a
// client that sends no parameters expects.
func TestUpdateFallsBackToTheSourceAddress(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	status, body := h.do(t, "", func(r *http.Request) {
		r.RemoteAddr = "203.0.113.50:40000"
	})
	asrt.Equal(http.StatusOK, status)
	asrt.Equal("good 203.0.113.50", body)
}

// A private or loopback address in a public record is a misconfigured client
// reporting its LAN address. Writing it would point the name somewhere
// unreachable.
//
// Crucially the request is refused rather than falling back to the source
// address: an explicit myip takes precedence (section 6.3), and substituting
// the observed source would publish the carrier-grade NAT address on exactly
// the DS-Lite connections that precedence exists for.
func TestUpdateRefusesUnpublishableAddresses(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	for _, addr := range []string{
		"192.168.1.5", "10.0.0.1", "172.16.0.1", "127.0.0.1", "169.254.1.1",
		"fd00::1", "::1", "fe80::1",
	} {
		status, body := h.do(t, "?myip="+addr, func(r *http.Request) {
			// A routable source address, so a fallback would visibly succeed.
			r.RemoteAddr = "203.0.113.77:40000"
		})
		asrt.Equal(http.StatusBadGateway, status, addr)
		asrt.Equal("dnserr", body, addr)
	}

	asrt.Empty(h.fake.records(), "no unpublishable address may reach the provider")

	// An unparsable address is refused the same way.
	status, body := h.do(t, "?myip=not-an-address")
	asrt.Equal(http.StatusBadGateway, status)
	asrt.Equal("dnserr", body)
}

// A host that manages only one family, sent both, writes the one it manages
// and ignores the other - that is not an error.
func TestUpdateIgnoresUnmanagedFamilies(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, nil)

	host, err := h.state.Hosts.Get(ctx, h.host)
	require.NoError(t, err)
	host.ManageAAAA = false
	require.NoError(t, h.state.Hosts.Put(ctx, host))

	status, body := h.do(t, "?myip=203.0.113.1&myipv6=2001:db8::1")
	asrt.Equal(http.StatusOK, status)
	asrt.Equal("good 203.0.113.1", body)

	records := h.fake.records()
	require.Len(t, records, 1)
	asrt.Equal(provider.TypeA, records[0].Type)

	// But a request carrying *only* the unmanaged family has nothing to do,
	// and says so rather than silently succeeding.
	h.fake.reset()
	status, body = h.do(t, "?myipv6=2001:db8::1")
	asrt.Equal(http.StatusBadRequest, status)
	asrt.Equal("nohost", body)
	asrt.Empty(h.fake.records())
}

func TestUpdateAuthentication(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	// No credentials at all.
	req := httptest.NewRequest(http.MethodGet, server.UpdatePath+"?myip=203.0.113.1", nil)
	req.TLS = &tlsState
	rec := httptest.NewRecorder()
	h.update.ServeHTTP(rec, req)

	asrt.Equal(http.StatusUnauthorized, rec.Code)
	asrt.Equal("badauth", strings.TrimSpace(rec.Body.String()))
	asrt.Contains(rec.Header().Get("WWW-Authenticate"), "Basic",
		"a realm invites a client to retry with credentials")

	// A wrong token.
	status, body := h.do(t, "?myip=203.0.113.1", func(r *http.Request) {
		r.SetBasicAuth(h.host, "not-the-token")
	})
	asrt.Equal(http.StatusUnauthorized, status)
	asrt.Equal("badauth", body)

	// A valid token presented for another host is `nohost`, not `badauth`.
	// DynDNS2 defines badauth as "the credentials do not match a real user"
	// and nohost as "the hostname does not exist in this account", and this is
	// the latter: the token is a real credential, used outside its scope.
	//
	// It reveals nothing a correct token did not already grant - omitting the
	// hostname would succeed for the token's own host anyway.
	status, body = h.do(t, "?myip=203.0.113.1", func(r *http.Request) {
		r.SetBasicAuth("other.example.org", h.token)
	})
	asrt.Equal(http.StatusBadRequest, status)
	asrt.Equal("nohost", body)

	asrt.Empty(h.fake.records(), "no failed authentication may reach the provider")
}

// The hostname parameter must agree with the authenticated host: a token is
// scoped to one name, so a mismatch is an attempt to use it for another.
func TestUpdateRejectsAHostnameMismatch(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	status, body := h.do(t, "?hostname=elsewhere.example.org&myip=203.0.113.1")
	asrt.Equal(http.StatusBadRequest, status)
	asrt.Equal("nohost", body)
	asrt.Empty(h.fake.records())

	// A matching hostname, in any case, is fine - DNS is case-insensitive.
	status, body = h.do(t, "?hostname=DYN.Example.ORG&myip=203.0.113.1")
	asrt.Equal(http.StatusOK, status)
	asrt.Equal("good 203.0.113.1", body)
}

// A revoked token must stop working at once: authentication is a store lookup
// on every request, with nothing cached.
func TestUpdateHonoursRevocationImmediately(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, nil)

	status, _ := h.do(t, "?myip=203.0.113.1")
	require.Equal(t, http.StatusOK, status)

	tokens, err := h.state.Tokens.List(ctx, h.host)
	require.NoError(t, err)
	require.Len(t, tokens, 1)

	_, err = h.state.Tokens.Revoke(ctx, tokens[0].ID)
	require.NoError(t, err)

	status, body := h.do(t, "?myip=203.0.113.9")
	asrt.Equal(http.StatusUnauthorized, status)
	asrt.Equal("badauth", body)
}

// A provider failure is dnserr, and the address must NOT be recorded - the
// stored address is what answers nochg, so recording a failed write would make
// the client stop retrying.
func TestUpdateProviderFailureDoesNotRecordTheAddress(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, nil)

	h.fake.setFailure(errors.New("credentials rejected"))

	status, body := h.do(t, "?myip=203.0.113.1")
	asrt.Equal(http.StatusBadGateway, status)
	asrt.Equal("dnserr", body)

	host, err := h.state.Hosts.Get(ctx, h.host)
	asrt.NoError(err)
	asrt.Empty(host.LastIPv4, "a failed write must not be recorded as applied")

	// And the failure is reported as an event.
	pending, err := h.state.Outbox.Pending(ctx, 0)
	asrt.NoError(err)

	var sawFailure bool
	for _, entry := range pending {
		if entry.Event.Type == app.EventHostUpdateFailed {
			sawFailure = true
			asrt.Equal(h.host, entry.Event.Subject)
		}
	}
	asrt.True(sawFailure, "a provider failure must emit host.update_failed")

	// Once the provider recovers, the same address goes through - it was never
	// recorded as applied.
	h.fake.setFailure(nil)

	status, body = h.do(t, "?myip=203.0.113.1")
	asrt.Equal(http.StatusOK, status)
	asrt.Equal("good 203.0.113.1", body)
}

// A successful update emits host.updated; a nochg emits nothing, because
// nothing happened.
func TestUpdateEvents(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, nil)

	require.NoError(t, drainOutbox(ctx, h))

	status, _ := h.do(t, "?myip=203.0.113.1")
	require.Equal(t, http.StatusOK, status)

	pending, err := h.state.Outbox.Pending(ctx, 0)
	require.NoError(t, err)

	var updates int
	for _, entry := range pending {
		if entry.Event.Type == app.EventHostUpdated {
			updates++
			asrt.Equal("203.0.113.1", entry.Event.Field("ipv4"))
		}
	}
	asrt.Equal(1, updates)

	require.NoError(t, drainOutbox(ctx, h))

	// A nochg must emit nothing.
	status, _ = h.do(t, "?myip=203.0.113.1")
	require.Equal(t, http.StatusOK, status)

	pending, err = h.state.Outbox.Pending(ctx, 0)
	asrt.NoError(err)
	asrt.Empty(pending, "an unchanged address is not an event: nothing happened")
}

// drainOutbox clears the outbox so a test can assert on what one action adds.
func drainOutbox(ctx context.Context, h *harness) error {
	pending, err := h.state.Outbox.Pending(ctx, 0)
	if err != nil {
		return err
	}

	for _, entry := range pending {
		if err := h.state.Outbox.MarkDelivered(ctx, entry.Event.ID); err != nil {
			return err
		}
	}

	return nil
}

// The per-host limit caps provider calls for a legitimate but misconfigured
// client, and answers with Retry-After so a well-behaved one backs off.
func TestUpdateRateLimitPerHost(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, nil)

	settings, err := h.state.LoadSettings(ctx)
	require.NoError(t, err)
	settings.RateLimitPerHost = 3
	settings.RateLimitPerSource = 0 // isolate the per-host limit
	require.NoError(t, h.state.ApplySettings(ctx, settings))

	// Each request changes the address, so none is short-circuited as nochg.
	addresses := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}
	for _, addr := range addresses {
		status, _ := h.do(t, "?myip="+addr)
		asrt.Equal(http.StatusOK, status, addr)
	}

	req := httptest.NewRequest(http.MethodGet, server.UpdatePath+"?myip=203.0.113.4", nil)
	req.SetBasicAuth(h.host, h.token)
	req.TLS = &tlsState
	rec := httptest.NewRecorder()
	h.update.ServeHTTP(rec, req)

	asrt.Equal(http.StatusTooManyRequests, rec.Code)
	asrt.Equal("abuse", strings.TrimSpace(rec.Body.String()))
	asrt.NotEmpty(rec.Header().Get("Retry-After"),
		"a limit without Retry-After is a wall rather than back-pressure")
	asrt.Len(h.fake.records(), 3, "a rate-limited request must not reach the provider")
}

// The per-source limit is applied before authentication, because its job is to
// slow an attacker guessing tokens - a limit applied only after a successful
// authentication would never see them.
func TestUpdateRateLimitPerSourceAppliesBeforeAuthentication(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, nil)

	settings, err := h.state.LoadSettings(ctx)
	require.NoError(t, err)
	settings.RateLimitPerSource = 3
	settings.RateLimitPerHost = 0
	require.NoError(t, h.state.ApplySettings(ctx, settings))

	guess := func() int {
		req := httptest.NewRequest(http.MethodGet, server.UpdatePath+"?myip=203.0.113.1", nil)
		req.SetBasicAuth(h.host, "wrong-token")
		req.RemoteAddr = "203.0.113.99:40000"
		req.TLS = &tlsState
		rec := httptest.NewRecorder()
		h.update.ServeHTTP(rec, req)

		return rec.Code
	}

	for range 3 {
		asrt.Equal(http.StatusUnauthorized, guess())
	}

	// The fourth is rate limited rather than merely rejected, and it never
	// reaches the token lookup.
	asrt.Equal(http.StatusTooManyRequests, guess())
}
