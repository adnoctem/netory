package app_test

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
	"github.com/adnoctem/netory/pkg/log"
)

func silentLogger(t *testing.T) *log.Logger {
	t.Helper()

	return log.New(log.WithOutput(&strings.Builder{}), log.WithLevel(slog.LevelError))
}

// newRepos returns host and token repositories over a real in-memory Badger
// store. Using the real store rather than a fake means these tests exercise
// the same code path the server does.
func newRepos(t *testing.T) (*app.Hosts, *app.Tokens) {
	t.Helper()

	store, err := badgerkv.New(badgerkv.Options{InMemory: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	hostsHandle, err := kv.In(store, "hosts")
	require.NoError(t, err)

	tokensHandle, err := kv.In(store, "tokens")
	require.NoError(t, err)

	return app.NewHosts(hostsHandle), app.NewTokens(tokensHandle, silentLogger(t))
}

// DNS names are case-insensitive, so a client authenticating as
// "Dyn.Example.ORG" must reach the same host as one using lower case.
func TestNormaliseHostname(t *testing.T) {
	asrt := assert.New(t)

	for input, want := range map[string]string{
		"dyn.example.org":   "dyn.example.org",
		"Dyn.Example.ORG":   "dyn.example.org",
		"dyn.example.org.":  "dyn.example.org",
		"  dyn.example.org": "dyn.example.org",
		"DYN.EXAMPLE.ORG.":  "dyn.example.org",
	} {
		asrt.Equal(want, app.NormaliseHostname(input), "input %q", input)
	}
}

func TestValidateHostname(t *testing.T) {
	asrt := assert.New(t)

	for _, name := range []string{
		"dyn.example.org",
		"a.b.c.example.org",
		"example.org",
		"host-1.example.org",
		"_acme-challenge.example.org",
	} {
		asrt.NoError(app.ValidateHostname(name), name)
	}

	for label, name := range map[string]string{
		"empty":           "",
		"not qualified":   "localhost",
		"empty label":     "dyn..example.org",
		"trailing hyphen": "dyn-.example.org",
		"leading hyphen":  "-dyn.example.org",
		"space":           "dyn host.example.org",
		"uppercase":       "DYN.example.org",
		"an IPv4 address": "203.0.113.1",
		"an IPv6 address": "2001:db8::1",
		"over-long label": strings.Repeat("a", 64) + ".example.org",
		"over-long name":  strings.Repeat("a.", 130) + "example.org",
	} {
		asrt.Error(app.ValidateHostname(name), label)
	}

	// A bare address is rejected explicitly, because the record it would
	// produce can never resolve.
	err := app.ValidateHostname("203.0.113.1")
	asrt.Contains(err.Error(), "IP address")
}

func TestHostsAddGetList(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	hosts, _ := newRepos(t)

	require.NoError(t, hosts.Add(ctx, app.Host{
		Name: "B.example.org", Provider: "cf", ManageA: true, ManageAAAA: true,
	}))
	require.NoError(t, hosts.Add(ctx, app.Host{
		Name: "a.example.org", Provider: "cf", ManageA: true,
	}))

	// Stored under the normalised name, so a mixed-case lookup finds it.
	got, err := hosts.Get(ctx, "b.EXAMPLE.org")
	asrt.NoError(err)
	asrt.Equal("b.example.org", got.Name)
	asrt.True(got.ManageAAAA)
	asrt.False(got.CreatedAt.IsZero())

	all, err := hosts.List(ctx)
	asrt.NoError(err)
	require.Len(t, all, 2)
	asrt.Equal("a.example.org", all[0].Name, "List must be sorted, since Scan's order is unspecified")
	asrt.Equal("b.example.org", all[1].Name)

	exists, err := hosts.Exists(ctx, "a.example.org")
	asrt.NoError(err)
	asrt.True(exists)

	exists, err = hosts.Exists(ctx, "nope.example.org")
	asrt.NoError(err)
	asrt.False(exists)
}

// `host add` on an existing name must not silently reset its provider and
// last-known addresses.
func TestHostsAddRejectsDuplicates(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	hosts, _ := newRepos(t)

	host := app.Host{Name: "dyn.example.org", Provider: "cf", ManageA: true}
	require.NoError(t, hosts.Add(ctx, host))

	host.Provider = "r53"
	err := hosts.Add(ctx, host)
	asrt.ErrorIs(err, app.ErrHostExists)

	// The original is untouched.
	got, err := hosts.Get(ctx, "dyn.example.org")
	asrt.NoError(err)
	asrt.Equal("cf", got.Provider)
}

func TestHostsAddValidates(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	hosts, _ := newRepos(t)

	asrt.Error(hosts.Add(ctx, app.Host{Name: "nope", Provider: "cf", ManageA: true}), "not fully qualified")
	asrt.Error(hosts.Add(ctx, app.Host{Name: "dyn.example.org", ManageA: true}), "no provider")

	// A host that manages neither family would accept updates and write
	// nothing, which looks like a working configuration and is not.
	err := hosts.Add(ctx, app.Host{Name: "dyn.example.org", Provider: "cf"})
	asrt.Error(err)
	asrt.Contains(err.Error(), "at least one")
}

func TestHostsGetMissing(t *testing.T) {
	ctx := context.Background()
	hosts, _ := newRepos(t)

	_, err := hosts.Get(ctx, "absent.example.org")
	assert.ErrorIs(t, err, app.ErrHostNotFound)
}

func TestHostsRemove(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	hosts, _ := newRepos(t)

	require.NoError(t, hosts.Add(ctx, app.Host{Name: "dyn.example.org", Provider: "cf", ManageA: true}))
	require.NoError(t, hosts.Remove(ctx, "DYN.example.org"))

	_, err := hosts.Get(ctx, "dyn.example.org")
	asrt.ErrorIs(err, app.ErrHostNotFound)

	// Removing an absent host is an error, not a silent success: an operator
	// typing the wrong name should be told.
	asrt.ErrorIs(hosts.Remove(ctx, "dyn.example.org"), app.ErrHostNotFound)
}

// RecordUpdate is what makes a `nochg` response free: the stored address is
// what an update is compared against.
func TestHostsRecordUpdate(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	hosts, _ := newRepos(t)

	require.NoError(t, hosts.Add(ctx, app.Host{
		Name: "dyn.example.org", Provider: "cf", ManageA: true, ManageAAAA: true,
	}))

	require.NoError(t, hosts.RecordUpdate(ctx, "dyn.example.org", "203.0.113.1", ""))

	got, err := hosts.Get(ctx, "dyn.example.org")
	asrt.NoError(err)
	asrt.Equal("203.0.113.1", got.LastIPv4)
	asrt.Empty(got.LastIPv6, "an empty address must not overwrite the other family")
	asrt.False(got.LastUpdateAt.IsZero())

	// The other family updates independently: AAAA records are updated
	// separately from A.
	require.NoError(t, hosts.RecordUpdate(ctx, "dyn.example.org", "", "2001:db8::1"))

	got, err = hosts.Get(ctx, "dyn.example.org")
	asrt.NoError(err)
	asrt.Equal("203.0.113.1", got.LastIPv4, "the IPv4 address must survive an IPv6-only update")
	asrt.Equal("2001:db8::1", got.LastIPv6)

	asrt.Equal("203.0.113.1", got.LastAddress(false))
	asrt.Equal("2001:db8::1", got.LastAddress(true))
	asrt.True(got.Manages(false))
	asrt.True(got.Manages(true))
}

// Put must preserve CreatedAt: an edit is not a re-creation.
func TestHostsPutPreservesCreatedAt(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	hosts, _ := newRepos(t)

	require.NoError(t, hosts.Add(ctx, app.Host{Name: "dyn.example.org", Provider: "cf", ManageA: true}))

	original, err := hosts.Get(ctx, "dyn.example.org")
	require.NoError(t, err)

	original.Provider = "r53"
	require.NoError(t, hosts.Put(ctx, original))

	updated, err := hosts.Get(ctx, "dyn.example.org")
	asrt.NoError(err)
	asrt.Equal("r53", updated.Provider)
	asrt.Equal(original.CreatedAt, updated.CreatedAt)
	asrt.False(updated.UpdatedAt.Before(original.UpdatedAt))

	// Put on an absent host is an error, so it cannot be used to create one
	// and skip validation.
	asrt.ErrorIs(hosts.Put(ctx, app.Host{Name: "absent.example.org"}), app.ErrHostNotFound)
}

func TestHostRelativeName(t *testing.T) {
	asrt := assert.New(t)

	name, err := app.Host{Name: "dyn.example.org"}.RelativeName("example.org")
	asrt.NoError(err)
	asrt.Equal("dyn", name)

	name, err = app.Host{Name: "a.b.example.org"}.RelativeName("example.org")
	asrt.NoError(err)
	asrt.Equal("a.b", name)

	// A host at the zone apex relativises to the empty name, which is what the
	// provider interface expects.
	name, err = app.Host{Name: "example.org"}.RelativeName("example.org")
	asrt.NoError(err)
	asrt.Empty(name)

	// Case and a trailing dot on the zone must not matter.
	name, err = app.Host{Name: "dyn.example.org"}.RelativeName("EXAMPLE.ORG.")
	asrt.NoError(err)
	asrt.Equal("dyn", name)

	// A host assigned to the wrong provider is caught here rather than
	// producing a record in someone else's zone.
	_, err = app.Host{Name: "dyn.example.org"}.RelativeName("other.example")
	asrt.Error(err)
	asrt.Contains(err.Error(), "right provider")

	// A name that merely ends with the zone's characters is not inside it.
	_, err = app.Host{Name: "dynexample.org"}.RelativeName("example.org")
	asrt.Error(err)
}

func TestTokensCreateAndAuthenticate(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	_, tokens := newRepos(t)

	value, token, err := tokens.Create(ctx, "dyn.example.org", "fritzbox")
	require.NoError(t, err)

	asrt.NotEmpty(value)
	asrt.Equal("dyn.example.org", token.Host)
	asrt.Equal("fritzbox", token.Label)
	asrt.NotEmpty(token.ID)
	asrt.False(token.CreatedAt.IsZero())

	// The value never appears in the stored record, which is what makes "shown
	// once, never retrievable" true rather than a convention.
	listed, err := tokens.List(ctx, "")
	require.NoError(t, err)
	require.Len(t, listed, 1)
	asrt.NotContains(listed[0].ID, value)
	asrt.Equal(token.ID, listed[0].ID)

	authed, err := tokens.AuthenticateFor(ctx, "dyn.example.org", value)
	asrt.NoError(err)
	asrt.Equal(token.ID, authed.ID)

	// The claimed host is normalised, so case cannot defeat authentication.
	authed, err = tokens.AuthenticateFor(ctx, "DYN.Example.ORG", value)
	asrt.NoError(err)
	asrt.Equal(token.ID, authed.ID)

	// And the token alone resolves to its host, with no hostname claimed. A
	// token belongs to exactly one host, so it already says which.
	authed, err = tokens.Authenticate(ctx, value)
	asrt.NoError(err)
	asrt.Equal(token.ID, authed.ID)
	asrt.Equal("dyn.example.org", authed.Host)
}

func TestTokensAuthenticateRejections(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	_, tokens := newRepos(t)

	value, _, err := tokens.Create(ctx, "dyn.example.org", "")
	require.NoError(t, err)

	_, err = tokens.AuthenticateFor(ctx, "dyn.example.org", "")
	asrt.ErrorIs(err, app.ErrTokenNotFound, "an empty token must not authenticate")

	_, err = tokens.Authenticate(ctx, "")
	asrt.ErrorIs(err, app.ErrTokenNotFound)

	_, err = tokens.AuthenticateFor(ctx, "dyn.example.org", "wrong-token-value")
	asrt.ErrorIs(err, app.ErrTokenNotFound)

	_, err = tokens.Authenticate(ctx, "wrong-token-value")
	asrt.ErrorIs(err, app.ErrTokenNotFound)

	// One token belongs to one host. A valid token presented for a different
	// host is a mismatch, not a success - this is the check that keeps a token
	// scoped, and it is why loosening the username requirement does not
	// loosen scoping.
	_, err = tokens.AuthenticateFor(ctx, "other.example.org", value)
	asrt.ErrorIs(err, app.ErrTokenMismatch)
}

// Generated tokens must be unique and full-entropy; that is the reason no slow
// password hash is used to store them.
func TestTokensAreUnique(t *testing.T) {
	asrt := assert.New(t)

	seen := make(map[string]struct{}, 512)
	for range 512 {
		value, err := app.GenerateToken()
		require.NoError(t, err)

		_, dup := seen[value]
		if !asrt.False(dup, "GenerateToken repeated itself") {
			return
		}
		seen[value] = struct{}{}

		// Raw URL base64 so the value survives a shell, an environment
		// variable and a URL without quoting - a dynDNS client configuration
		// is frequently a URL with the token in it.
		asrt.NotContains(value, "+")
		asrt.NotContains(value, "/")
		asrt.NotContains(value, "=")
	}
}

func TestHashTokenIsStable(t *testing.T) {
	asrt := assert.New(t)

	asrt.Equal(app.HashToken("abc"), app.HashToken("abc"))
	asrt.NotEqual(app.HashToken("abc"), app.HashToken("abc "), "a one-byte difference must change the hash")
	asrt.Len(app.HashToken("abc"), 64, "a hex-encoded SHA-256 is 64 characters")
}

// A host may have several tokens, which is what makes rotation possible
// without downtime.
func TestTokensSeveralPerHost(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	_, tokens := newRepos(t)

	first, _, err := tokens.Create(ctx, "dyn.example.org", "router")
	require.NoError(t, err)

	second, _, err := tokens.Create(ctx, "dyn.example.org", "laptop")
	require.NoError(t, err)

	for _, value := range []string{first, second} {
		_, err := tokens.AuthenticateFor(ctx, "dyn.example.org", value)
		asrt.NoError(err, "both tokens must work")
	}

	listed, err := tokens.List(ctx, "dyn.example.org")
	asrt.NoError(err)
	asrt.Len(listed, 2)
}

func TestTokensListFiltersByHost(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	_, tokens := newRepos(t)

	_, _, err := tokens.Create(ctx, "a.example.org", "")
	require.NoError(t, err)

	_, _, err = tokens.Create(ctx, "b.example.org", "")
	require.NoError(t, err)

	all, err := tokens.List(ctx, "")
	asrt.NoError(err)
	asrt.Len(all, 2)
	asrt.Equal("a.example.org", all[0].Host, "List must be sorted by host")

	only, err := tokens.List(ctx, "B.example.org")
	asrt.NoError(err)
	require.Len(t, only, 1)
	asrt.Equal("b.example.org", only[0].Host)
}

// Revocation takes effect immediately, because authentication is a store
// lookup on every request with nothing cached.
func TestTokensRevoke(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	_, tokens := newRepos(t)

	value, token, err := tokens.Create(ctx, "dyn.example.org", "")
	require.NoError(t, err)

	revoked, err := tokens.Revoke(ctx, token.ID)
	asrt.NoError(err)
	asrt.Equal(token.ID, revoked.ID)

	_, err = tokens.AuthenticateFor(ctx, "dyn.example.org", value)
	asrt.ErrorIs(err, app.ErrTokenNotFound, "a revoked token must stop working at once")

	_, err = tokens.Authenticate(ctx, value)
	asrt.ErrorIs(err, app.ErrTokenNotFound, "revocation must hold without a claimed host too")

	// Revoking twice, or revoking an unknown ID, is an error rather than a
	// silent success.
	_, err = tokens.Revoke(ctx, token.ID)
	asrt.ErrorIs(err, app.ErrTokenNotFound)

	_, err = tokens.Revoke(ctx, "")
	asrt.Error(err)
}

// The new token is issued before the old one is revoked, so a failure between
// the two leaves the host with two working tokens rather than none. A locked-out
// router stops updating and nobody notices until the address changes.
func TestTokensRotate(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	_, tokens := newRepos(t)

	oldValue, oldToken, err := tokens.Create(ctx, "dyn.example.org", "fritzbox")
	require.NoError(t, err)

	newValue, newToken, err := tokens.Rotate(ctx, oldToken.ID, "")
	require.NoError(t, err)

	asrt.NotEqual(oldValue, newValue)
	asrt.NotEqual(oldToken.ID, newToken.ID)
	asrt.Equal("dyn.example.org", newToken.Host)
	asrt.Equal("fritzbox", newToken.Label, "the label carries over when none is given")

	_, err = tokens.AuthenticateFor(ctx, "dyn.example.org", newValue)
	asrt.NoError(err)

	_, err = tokens.AuthenticateFor(ctx, "dyn.example.org", oldValue)
	asrt.ErrorIs(err, app.ErrTokenNotFound, "rotation revokes the old token")

	listed, err := tokens.List(ctx, "dyn.example.org")
	asrt.NoError(err)
	asrt.Len(listed, 1)

	// A new label replaces the old one.
	_, relabelled, err := tokens.Rotate(ctx, newToken.ID, "new-router")
	asrt.NoError(err)
	asrt.Equal("new-router", relabelled.Label)

	_, _, err = tokens.Rotate(ctx, "no-such-id", "")
	asrt.Error(err)
}

// A host's credentials must not outlive the host.
func TestTokensRevokeAllFor(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	_, tokens := newRepos(t)

	for range 3 {
		_, _, err := tokens.Create(ctx, "dyn.example.org", "")
		require.NoError(t, err)
	}

	keepValue, _, err := tokens.Create(ctx, "other.example.org", "")
	require.NoError(t, err)

	removed, err := tokens.RevokeAllFor(ctx, "DYN.example.org")
	asrt.NoError(err)
	asrt.Equal(3, removed)

	listed, err := tokens.List(ctx, "dyn.example.org")
	asrt.NoError(err)
	asrt.Empty(listed)

	// Another host's tokens are untouched.
	_, err = tokens.AuthenticateFor(ctx, "other.example.org", keepValue)
	asrt.NoError(err)

	removed, err = tokens.RevokeAllFor(ctx, "nobody.example.org")
	asrt.NoError(err)
	asrt.Zero(removed)
}

// The update endpoint handles concurrent requests and each authenticates, so
// the token path has to be safe under load.
func TestTokensConcurrentAuthenticate(t *testing.T) {
	ctx := context.Background()
	_, tokens := newRepos(t)

	value, _, err := tokens.Create(ctx, "dyn.example.org", "")
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for range 20 {
				if _, err := tokens.AuthenticateFor(ctx, "dyn.example.org", value); err != nil {
					t.Errorf("AuthenticateFor: %v", err)

					return
				}
			}
		}()
	}
	wg.Wait()
}

// Creating tokens concurrently must not lose any: each gets its own random
// value, so no two collide on the hash key.
func TestTokensConcurrentCreate(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	_, tokens := newRepos(t)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			for range 8 {
				if _, _, err := tokens.Create(ctx, "dyn.example.org", ""); err != nil {
					t.Errorf("Create: %v", err)

					return
				}
			}
		}(i)
	}
	wg.Wait()

	listed, err := tokens.List(ctx, "dyn.example.org")
	asrt.NoError(err)
	asrt.Len(listed, 64, "no token may be lost under concurrent creation")
}
