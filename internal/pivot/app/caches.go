package app

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adnoctem/netory/internal/pivot/auth"
)

// settingsCache holds the last loaded settings document.
//
// The request path reads settings per request - the frontend mode, the cache
// behaviour, the access-log mode - and a Valkey round trip for a document that
// changes rarely would be a cost paid on every request for nothing. The cache
// is refreshed when this replica changes a setting, and on the other replicas
// by the rule reloader, which is why a settings change bumps the rule version.
type settingsCache struct {
	value atomic.Pointer[Settings]
}

func newSettingsCache() *settingsCache {
	cache := &settingsCache{}
	defaults := DefaultSettings()
	cache.value.Store(&defaults)

	return cache
}

func (c *settingsCache) load() Settings {
	if settings := c.value.Load(); settings != nil {
		return *settings
	}

	return DefaultSettings()
}

func (c *settingsCache) store(settings Settings) {
	// Stored as a copy, so a caller mutating what it passed cannot change
	// what later readers see.
	snapshot := settings
	c.value.Store(&snapshot)
}

// backendCache holds one backend authenticator per client.
//
// It exists for the oauth2 mode's in-process token state. Building a fresh
// authenticator per request would discard that state, so every request would
// find no token and go to the backend's token endpoint - turning one token
// request per ten minutes into one per proxied request, which is both slow and
// a good way to be rate-limited by the thing pivot is shielding.
//
// Keyed by client id and generation. The generation is bumped when a client's
// credentials change, so a rotation takes effect on the next request rather
// than when the old backend token happens to expire.
type backendCache struct {
	state *State
	http  *http.Client
	now   func() time.Time

	mu      sync.Mutex
	entries map[string]*backendEntry
}

// backendEntry is one client's authenticator and the credentials it was built
// from.
type backendEntry struct {
	backend auth.Backend

	// mode and fingerprint detect a credential change without storing the
	// credentials a second time: the fingerprint is the sealed blob's hash,
	// which changes whenever the record is rewritten.
	mode        auth.BackendMode
	fingerprint string
}

func newBackendCache(state *State, client *http.Client, now func() time.Time) *backendCache {
	return &backendCache{
		state:   state,
		http:    client,
		now:     now,
		entries: map[string]*backendEntry{},
	}
}

// get returns the authenticator for a client, building it if needed.
func (c *backendCache) get(client Client) (auth.Backend, error) {
	fingerprint := auth.Hash(string(client.SealedBackend))

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.entries[client.ID]; ok {
		if entry.mode == client.Backend.Mode && entry.fingerprint == fingerprint {
			return entry.backend, nil
		}
	}

	settings := c.state.settings.load()

	backend, err := auth.NewBackend(client.Backend, auth.BackendOptions{
		BaseURL:    settings.BackendURL,
		ClientKey:  client.ID,
		Cache:      c.state.tokenCache(),
		HTTPClient: c.http,
		Now:        c.now,
	})
	if err != nil {
		return nil, err
	}

	c.entries[client.ID] = &backendEntry{
		backend:     backend,
		mode:        client.Backend.Mode,
		fingerprint: fingerprint,
	}

	return backend, nil
}

// forget drops a client's authenticator.
func (c *backendCache) forget(client string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.entries, client)
}

// len reports how many authenticators are cached, for `config view`.
func (c *backendCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}
