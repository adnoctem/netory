package app_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/internal/pivot/config"
	"github.com/adnoctem/netory/internal/pivot/rules"
	"github.com/adnoctem/netory/pkg/kv/valkeykv"
	"github.com/adnoctem/netory/pkg/log"
	"github.com/adnoctem/netory/pkg/secret"
)

func silentLogger(t *testing.T) *log.Logger {
	t.Helper()

	return log.New(log.WithOutput(&strings.Builder{}), log.WithLevel(slog.LevelError))
}

// testDB is the Valkey logical database these tests use.
//
// Not database 0, and the reason is a bug this caused: pivot's namespaces are
// compile-time constants, so these tests cannot scope themselves with a
// per-test prefix the way pkg/kv/valkeykv's do. The first version cleaned up
// with `SCAN *` plus `DEL`, which deleted the conformance suite's keys out
// from under it when `go test ./...` ran the two packages at once - and
// presented as the conformance suite failing. A separate database keeps the
// two apart, and the cleanup below is still scoped to pivot's own prefixes so
// nothing here can delete a key it did not write.
const testDB = 1

// newState builds application state against a real Valkey, in a database of
// its own.
//
// A real Valkey rather than Badger, even though kv.Store makes either work:
// pivot's whole state model is "several replicas, one store", and the pieces
// worth testing here - the rule version counter, the pub/sub announcement, the
// shared token cache - are Valkey's behaviour. The conformance suite is what
// establishes the two stores agree on the rest.
func newState(t *testing.T) *app.State {
	t.Helper()

	addr := valkeyAddress(t)

	store, err := valkeykv.New(valkeykv.Options{Address: []string{addr}, DB: testDB})
	require.NoError(t, err)

	raw, err := secret.Generate()
	require.NoError(t, err)

	sec, err := secret.Parse(raw)
	require.NoError(t, err)

	cfg := config.Default()
	cfg.Replica = fmt.Sprintf("replica-%s-%d", runID, namespaceCounter.Add(1))

	state, err := app.New(context.Background(), app.Options{
		Config: cfg,
		Logger: silentLogger(t),
		Store:  store,
		Secret: sec,

		// Polling off: the tests drive reloads themselves, so a background
		// loop would race their assertions about when a rebuild happened.
		ReloadPoll: -1,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		flushKeyspace(t, addr, state)
		_ = state.Close(context.Background())
	})

	return state
}

// pivotNamespaces are the key prefixes pivot writes, which is the scope of
// the cleanup.
//
// Listed explicitly rather than matched with `*`: a wildcard flush is a tool
// that deletes whatever happens to be there, and what happens to be there on
// a developer's Valkey is not this suite's business.
var pivotNamespaces = []string{
	app.NamespaceClients, app.NamespaceTokens, app.NamespaceConfig,
	app.NamespaceSettings, app.NamespaceOutbox, app.NamespaceRateLimit,
	app.NamespaceCache, app.NamespaceAudit,
}

// flushKeyspace removes everything this test wrote.
//
// Needed because pivot's namespaces are shared between tests rather than
// per-test - they are compile-time constants - so a run that left its keys
// behind would be seen by the next one. The tests in this package therefore do
// not call t.Parallel, and each clears up after itself.
func flushKeyspace(t *testing.T, addr string, state *app.State) {
	t.Helper()

	ctx := context.Background()
	client := state.Store.Client()

	for _, namespace := range pivotNamespaces {
		var cursor uint64

		for {
			entry, err := client.Do(ctx, client.B().Scan().
				Cursor(cursor).Match(namespace+":*").Count(512).Build()).AsScanEntry()
			if err != nil {
				t.Logf("could not scan %s to clean up: %v", namespace, err)

				break
			}

			if len(entry.Elements) > 0 {
				err := client.Do(ctx, client.B().Del().Key(entry.Elements...).Build()).Error()
				if err != nil {
					t.Logf("could not delete %d keys in %s: %v", len(entry.Elements), namespace, err)
				}
			}

			cursor = entry.Cursor
			if cursor == 0 {
				break
			}
		}
	}
}

// testBackend is a usable backend configuration.
func testBackend() auth.BackendConfig {
	return auth.BackendConfig{
		Mode:     auth.BackendBasic,
		Username: "integration",
		Password: "integration-secret",
	}
}

func TestClientLifecycle(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	created, secret, err := state.Clients.Create(ctx, app.Client{
		Name:      "Acme GmbH",
		Backend:   testBackend(),
		RateLimit: app.RateLimit{Capacity: 10, PerSecond: 1},
		CreatedBy: "operator(uid=1000)",
	})
	require.NoError(t, err)

	asrt := assert.New(t)
	asrt.NotEmpty(created.ID)
	asrt.NotEmpty(secret)
	asrt.Equal(auth.Hash(secret), created.SecretHash)

	// Read back, with the backend credentials decrypted.
	fetched, err := state.Clients.Get(ctx, created.ID)
	require.NoError(t, err)
	asrt.Equal("Acme GmbH", fetched.Name)
	asrt.Equal("integration", fetched.Backend.Username)
	asrt.Equal("integration-secret", fetched.Backend.Password)

	// Authentication works with the secret and not without it.
	authenticated, err := state.Clients.Authenticate(ctx, created.ID, secret)
	require.NoError(t, err)
	asrt.Equal(created.ID, authenticated.ID)

	_, err = state.Clients.Authenticate(ctx, created.ID, "wrong")
	asrt.ErrorIs(err, app.ErrClientNotFound,
		"a wrong secret and an unknown client are the same answer")

	_, err = state.Clients.Authenticate(ctx, "nonexistent", secret)
	asrt.ErrorIs(err, app.ErrClientNotFound)

	// Listed.
	clients, err := state.Clients.List(ctx)
	require.NoError(t, err)
	require.Len(t, clients, 1)
	asrt.Equal("integration-secret", clients[0].Backend.Password,
		"List must decrypt too, or `client list` could not report the backend mode")

	require.NoError(t, state.Clients.Remove(ctx, created.ID))

	_, err = state.Clients.Get(ctx, created.ID)
	asrt.ErrorIs(err, app.ErrClientNotFound)
}

// Valkey has no encryption at rest, so a snapshot must not hold a backend
// credential in the clear. This is the property §8 asks pivot to provide
// itself, asserted against the raw stored bytes.
func TestBackendCredentialsAreSealedInValkey(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	created, _, err := state.Clients.Create(ctx, app.Client{
		Name:      "Acme",
		Backend:   testBackend(),
		CreatedBy: "operator",
	})
	require.NoError(t, err)

	client := state.Store.Client()

	raw, err := client.Do(ctx, client.B().Get().
		Key("clients:client/"+created.ID).Build()).ToString()
	require.NoError(t, err)

	assert.NotContains(t, raw, "integration-secret",
		"the backend password must not be readable in the stored record")
	assert.NotContains(t, raw, "integration",
		"nor the backend username")
	assert.Contains(t, raw, "sealed_backend")
}

func TestClientRotateSecret(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	created, first, err := state.Clients.Create(ctx, app.Client{
		Name: "Acme", Backend: testBackend(), CreatedBy: "operator",
	})
	require.NoError(t, err)

	second, err := state.Clients.RotateSecret(ctx, created.ID)
	require.NoError(t, err)
	require.NotEqual(t, first, second)

	_, err = state.Clients.Authenticate(ctx, created.ID, first)
	assert.Error(t, err, "the old secret must stop working at once")

	_, err = state.Clients.Authenticate(ctx, created.ID, second)
	assert.NoError(t, err)
}

// A suspended client must stop authenticating without its credentials being
// reissued, so a customer can be restored rather than re-onboarded.
func TestClientDisable(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	created, secret, err := state.Clients.Create(ctx, app.Client{
		Name: "Acme", Backend: testBackend(), CreatedBy: "operator",
	})
	require.NoError(t, err)

	require.NoError(t, state.Clients.SetDisabled(ctx, created.ID, true))

	_, err = state.Clients.Authenticate(ctx, created.ID, secret)
	assert.ErrorIs(t, err, app.ErrClientDisabled)

	require.NoError(t, state.Clients.SetDisabled(ctx, created.ID, false))

	_, err = state.Clients.Authenticate(ctx, created.ID, secret)
	assert.NoError(t, err)
}

// A client record holding rules that do not compile would fail at the next
// reload, which is a request-path failure for a mistake made at `client add`.
func TestClientRulesAreValidatedOnWrite(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	broken := rules.Document{}
	broken.Rules.Allow = []rules.Rule{{Methods: []string{"DELETE"}, Glob: "/api/**"}}

	_, _, err := state.Clients.Create(ctx, app.Client{
		Name:      "Acme",
		Backend:   testBackend(),
		Rules:     &broken,
		CreatedBy: "operator",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, rules.ErrWriteMethod)
}

func TestClientValidation(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	for name, client := range map[string]app.Client{
		"no name":             {Backend: testBackend()},
		"name with a newline": {Name: "Acme\nInjected", Backend: testBackend()},
		"bad backend":         {Name: "Acme", Backend: auth.BackendConfig{Mode: "magic"}},
		"negative limit": {
			Name:      "Acme",
			Backend:   testBackend(),
			RateLimit: app.RateLimit{Capacity: -1},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := state.Clients.Create(ctx, client)
			assert.Error(t, err)
		})
	}
}

func TestTokenLifecycle(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	value, token, err := state.Tokens.Issue(ctx, "client-1", "ci", "", "operator", time.Minute)
	require.NoError(t, err)

	asrt := assert.New(t)
	asrt.NotEmpty(value)
	asrt.Equal(auth.Hash(value), token.Hash)
	asrt.Equal("client-1", token.ClientID)

	resolved, err := state.Tokens.Resolve(ctx, value)
	require.NoError(t, err)
	asrt.Equal("client-1", resolved.ClientID)

	// The store holds no usable token: the key is the hash and the record
	// carries only the hash.
	client := state.Store.Client()

	raw, err := client.Do(ctx, client.B().Get().Key("tokens:token/"+token.Hash).Build()).ToString()
	require.NoError(t, err)
	asrt.NotContains(raw, value, "the stored record must not hold the token itself")

	require.NoError(t, state.Tokens.Revoke(ctx, value))

	_, err = state.Tokens.Resolve(ctx, value)
	asrt.ErrorIs(err, app.ErrTokenNotFound)
}

// An expired token must not resolve, and the check is in pivot rather than
// left to the store's TTL rounding: kv.TTLGranularity makes a TTL a lower
// bound honoured to the second, and a bearer credential that works for a
// moment after it expired is not a property to leave to rounding.
func TestExpiredTokenDoesNotResolve(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	value, _, err := state.Tokens.Issue(ctx, "client-1", "", "", "operator", time.Second)
	require.NoError(t, err)

	_, err = state.Tokens.Resolve(ctx, value)
	require.NoError(t, err)

	time.Sleep(1200 * time.Millisecond)

	_, err = state.Tokens.Resolve(ctx, value)
	assert.ErrorIs(t, err, app.ErrTokenNotFound)
}

func TestTokenLifetimeBounds(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	_, _, err := state.Tokens.Issue(ctx, "c", "", "", "operator", 48*time.Hour)
	assert.ErrorIs(t, err, app.ErrTokenLifetime)

	// Zero takes the default rather than being refused.
	_, token, err := state.Tokens.Issue(ctx, "c", "", "", "operator", 0)
	require.NoError(t, err)
	assert.InDelta(t,
		app.DefaultTokenLifetime.Seconds(),
		token.ExpiresAt.Sub(token.IssuedAt).Seconds(), 1)
}

// A client whose record is gone must not keep working through a token issued
// before it went.
func TestRevokeForClient(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	for range 3 {
		_, _, err := state.Tokens.Issue(ctx, "client-1", "", "", "operator", time.Minute)
		require.NoError(t, err)
	}

	keep, _, err := state.Tokens.Issue(ctx, "client-2", "", "", "operator", time.Minute)
	require.NoError(t, err)

	removed, err := state.Tokens.RevokeForClient(ctx, "client-1")
	require.NoError(t, err)
	assert.Equal(t, 3, removed)

	remaining, err := state.Tokens.ListFor(ctx, "client-1")
	require.NoError(t, err)
	assert.Empty(t, remaining)

	// Another client's tokens are untouched.
	_, err = state.Tokens.Resolve(ctx, keep)
	assert.NoError(t, err)
}

// newStateSharing returns a second State over the same Valkey and the same
// secret, standing in for a second replica.
//
// The same secret matters: keys derived from it decrypt the credentials in
// Valkey, so a second replica with a different one would start cleanly and
// then fail every forward leg. That is the mistake the errors from Clients and
// Notifiers name explicitly, and sharing it here is what makes these tests
// about replication rather than about key management.
func newStateSharing(t *testing.T, other *app.State) *app.State {
	t.Helper()

	addr := valkeyAddress(t)

	store, err := valkeykv.New(valkeykv.Options{Address: []string{addr}, DB: testDB})
	require.NoError(t, err)

	cfg := other.Config
	cfg.Replica = fmt.Sprintf("replica-%s-%d", runID, namespaceCounter.Add(1))

	state, err := app.New(context.Background(), app.Options{
		Config:     cfg,
		Logger:     silentLogger(t),
		Store:      store,
		Secret:     other.Secret,
		ReloadPoll: -1,
	})
	require.NoError(t, err)

	t.Cleanup(func() { _ = state.Close(context.Background()) })

	return state
}
