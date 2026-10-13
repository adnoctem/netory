package cache_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/cache"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
	"github.com/adnoctem/netory/pkg/log"
)

// The Badger store rather than Valkey, because what is under test is the
// cache's behaviour against the kv.Store contract and not Valkey's. The
// conformance suite is what establishes the two stores agree.
func newStore(t *testing.T, key []byte) *cache.Store {
	t.Helper()

	store, err := badgerkv.New(badgerkv.Options{InMemory: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	handle, err := kv.In(store, "cache")
	require.NoError(t, err)

	codec, err := cache.NewCodec(key)
	require.NoError(t, err)

	cacheStore, err := cache.NewStore(cache.StoreOptions{
		Handle: handle,
		Codec:  codec,
		Logger: log.New(log.WithOutput(&strings.Builder{}), log.WithLevel(slog.LevelError)),
	})
	require.NoError(t, err)

	return cacheStore
}

func testKey(t *testing.T, client, path string) cache.Key {
	t.Helper()

	key, err := cache.NewKey(client, http.MethodGet, path, "", nil, true)
	require.NoError(t, err)

	return key
}

func testEntry() cache.Entry {
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	header.Set("ETag", `"abc"`)

	return cache.Entry{
		Status: http.StatusOK,
		Header: header,
		Body:   []byte(`{"total":1}`),
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t, nil)
	key := testKey(t, "client-1", "/api/search/product")

	_, found, err := store.Get(ctx, key, false)
	require.NoError(t, err)
	assert.False(t, found, "an empty cache is a miss, not an error")

	require.NoError(t, store.Put(ctx, key, testEntry(), time.Minute, false))

	entry, found, err := store.Get(ctx, key, false)
	require.NoError(t, err)
	require.True(t, found)

	asrt := assert.New(t)
	asrt.Equal(http.StatusOK, entry.Status)
	asrt.Equal(`{"total":1}`, string(entry.Body))
	asrt.Equal("application/json", entry.Header.Get("Content-Type"))
	asrt.Equal(`"abc"`, entry.Header.Get("ETag"))
	asrt.False(entry.StoredAt.IsZero(), "the store time is recorded so Age can be served")
}

// Two customers must never share an entry. This is the single most important
// property in the package: the cache sits in front of an API whose responses
// are mostly customer-specific.
func TestKeysAreScopedPerClient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t, nil)

	first := testKey(t, "client-1", "/api/search/product")
	second := testKey(t, "client-2", "/api/search/product")

	require.NotEqual(t, first.String(), second.String())

	require.NoError(t, store.Put(ctx, first, testEntry(), time.Minute, false))

	_, found, err := store.Get(ctx, second, false)
	require.NoError(t, err)
	assert.False(t, found, "one client's entry must not answer another's request")
}

// A shared route drops the client from the key, which is the one setting in
// the package that can leak between customers if it is wrong.
func TestSharedRoutesDropTheClientScope(t *testing.T) {
	t.Parallel()

	first, err := cache.NewKey("client-1", http.MethodGet, "/api/currency", "", nil, false)
	require.NoError(t, err)

	second, err := cache.NewKey("client-2", http.MethodGet, "/api/currency", "", nil, false)
	require.NoError(t, err)

	assert.Equal(t, first.String(), second.String())
	assert.False(t, first.Scoped())
}

func TestKeyCoversTheWholeRequest(t *testing.T) {
	t.Parallel()

	base, err := cache.NewKey("c", http.MethodGet, "/api/product", "page=1", []byte("body"), true)
	require.NoError(t, err)

	for name, build := range map[string]func() (cache.Key, error){
		"different method": func() (cache.Key, error) {
			return cache.NewKey("c", http.MethodPost, "/api/product", "page=1", []byte("body"), true)
		},
		"different path": func() (cache.Key, error) {
			return cache.NewKey("c", http.MethodGet, "/api/order", "page=1", []byte("body"), true)
		},
		"different query": func() (cache.Key, error) {
			return cache.NewKey("c", http.MethodGet, "/api/product", "page=2", []byte("body"), true)
		},
		"different body": func() (cache.Key, error) {
			return cache.NewKey("c", http.MethodGet, "/api/product", "page=1", []byte("other"), true)
		},
		"different client": func() (cache.Key, error) {
			return cache.NewKey("d", http.MethodGet, "/api/product", "page=1", []byte("body"), true)
		},
	} {
		other, err := build()
		require.NoError(t, err, name)
		assert.NotEqual(t, base.String(), other.String(), name)
	}
}

// Two orderings of the same parameters are the same request to any backend,
// so treating them as two entries would halve the hit rate for no benefit.
func TestQueryIsCanonicalized(t *testing.T) {
	t.Parallel()

	first, err := cache.NewKey("c", http.MethodGet, "/api/product", "limit=1&page=2", nil, true)
	require.NoError(t, err)

	second, err := cache.NewKey("c", http.MethodGet, "/api/product", "page=2&limit=1", nil, true)
	require.NoError(t, err)

	assert.Equal(t, first.String(), second.String())

	// A repeated parameter keeps its order, because for some APIs "?id=a&id=b"
	// is a list and sorting it would make two different requests equal.
	firstOrder, err := cache.NewKey("c", http.MethodGet, "/api/product", "id=a&id=b", nil, true)
	require.NoError(t, err)

	reversed, err := cache.NewKey("c", http.MethodGet, "/api/product", "id=b&id=a", nil, true)
	require.NoError(t, err)

	assert.NotEqual(t, firstOrder.String(), reversed.String())
}

// A truncated body hash would make two different requests share an entry,
// which is the one failure mode a cache must never have.
func TestOversizedBodyIsNotCacheable(t *testing.T) {
	t.Parallel()

	_, err := cache.NewKey("c", http.MethodPost, "/api/search/product", "",
		make([]byte, cache.MaxKeyedBodyBytes+1), true)
	assert.ErrorIs(t, err, cache.ErrBodyTooLarge)
}

// A key becomes a Valkey key, which kv.ValidateKey bounds at 1 KiB, while a
// path may be 4 KiB. Hashing is what keeps a long but legitimate request
// cacheable.
func TestKeyIsFixedLength(t *testing.T) {
	t.Parallel()

	long, err := cache.NewKey("c", http.MethodGet, "/api/"+strings.Repeat("a", 4000), "", nil, true)
	require.NoError(t, err)

	assert.Len(t, long.String(), 64)
	assert.NoError(t, kv.ValidateKey(long.String()))
}

// The backend's own caching directives must be honoured. A proxy
// that ignored them would be caching precisely what the backend was careful
// about.
func TestStorable(t *testing.T) {
	t.Parallel()

	t.Run("a plain 200 is storable", func(t *testing.T) {
		t.Parallel()

		ok, _ := cache.Storable(http.StatusOK, http.Header{}, 100)
		assert.True(t, ok)
	})

	for name, test := range map[string]struct {
		status int
		header map[string]string
		body   int
	}{
		"no-store":      {http.StatusOK, map[string]string{"Cache-Control": "no-store"}, 10},
		"private":       {http.StatusOK, map[string]string{"Cache-Control": "private, max-age=60"}, 10},
		"no-cache":      {http.StatusOK, map[string]string{"Cache-Control": "no-cache"}, 10},
		"sets a cookie": {http.StatusOK, map[string]string{"Set-Cookie": "session=abc"}, 10},
		"vary star":     {http.StatusOK, map[string]string{"Vary": "*"}, 10},
		"vary on a header the key misses": {
			http.StatusOK, map[string]string{"Vary": "Accept-Language"}, 10,
		},
		"a 404":             {http.StatusNotFound, nil, 10},
		"a 403":             {http.StatusForbidden, nil, 10},
		"a 500":             {http.StatusInternalServerError, nil, 10},
		"an oversized body": {http.StatusOK, nil, cache.MaxBodyBytes + 1},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			header := http.Header{}
			for key, value := range test.header {
				header.Set(key, value)
			}

			ok, reason := cache.Storable(test.status, header, test.body)
			assert.False(t, ok)
			assert.NotEmpty(t, reason, "a refusal must say why, for the log")
		})
	}

	// Accept-Encoding is the one Vary pivot can honour, because it forwards
	// and stores the encoded body as one unit.
	t.Run("vary on accept-encoding is fine", func(t *testing.T) {
		t.Parallel()

		header := http.Header{}
		header.Set("Vary", "Accept-Encoding")

		ok, _ := cache.Storable(http.StatusOK, header, 10)
		assert.True(t, ok)
	})
}

// A cached response is replayed to a different request than the one that
// produced it, so Set-Cookie above all must not come along.
func TestFilterHeadersIsAnAllowlist(t *testing.T) {
	t.Parallel()

	header := http.Header{}
	header.Set("Content-Type", "application/json")
	header.Set("ETag", `"x"`)
	header.Set("Set-Cookie", "session=secret")
	header.Set("Authorization", "Bearer leaked")
	header.Set("WWW-Authenticate", "Basic")
	header.Set("X-Backend-Invented-Later", "surprise")

	filtered := cache.FilterHeaders(header)

	asrt := assert.New(t)
	asrt.Equal("application/json", filtered.Get("Content-Type"))
	asrt.Equal(`"x"`, filtered.Get("ETag"))
	asrt.Empty(filtered.Get("Set-Cookie"), "a cached cookie would hand one customer another's session")
	asrt.Empty(filtered.Get("Authorization"))
	asrt.Empty(filtered.Get("WWW-Authenticate"))
	asrt.Empty(filtered.Get("X-Backend-Invented-Later"),
		"an allowlist means a header invented later is dropped rather than replayed")
}

func TestEncryptedEntries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	store := newStore(t, key)
	require.True(t, store.CanEncrypt())

	cacheKey := testKey(t, "client-1", "/api/search/order")
	require.NoError(t, store.Put(ctx, cacheKey, testEntry(), time.Minute, true))

	entry, found, err := store.Get(ctx, cacheKey, false)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, `{"total":1}`, string(entry.Body))
}

// The encrypt flag is set on routes whose responses can carry personal data, so
// storing one in the clear because no key was configured would break the exact
// promise the flag was turned on to make.
func TestEncryptedRouteWithoutAKeyFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t, nil)
	require.False(t, store.CanEncrypt())

	err := store.Put(ctx, testKey(t, "c", "/api/search/order"), testEntry(), time.Minute, true)
	assert.ErrorIs(t, err, cache.ErrEncryptionUnavailable)
}

// The flag byte is covered by the GCM tag, so an encrypted entry cannot be
// presented as a plaintext one by flipping it.
func TestSealedEntryIsTamperEvident(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)

	codec, err := cache.NewCodec(key)
	require.NoError(t, err)

	sealed, err := codec.Encode(testEntry(), true)
	require.NoError(t, err)

	for name, mutate := range map[string]func([]byte){
		"the flag byte":  func(b []byte) { b[7] = 0 },
		"the nonce":      func(b []byte) { b[10] ^= 0xff },
		"the ciphertext": func(b []byte) { b[len(b)-1] ^= 0xff },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tampered := make([]byte, len(sealed))
			copy(tampered, sealed)
			mutate(tampered)

			_, err := codec.Decode(tampered, false)
			assert.Error(t, err, "a tampered entry must not decode")
		})
	}
}

// Two pivot versions share one Valkey while a deployment rolls, and the older
// must not try to read the newer one's entries.
func TestEntryFromANewerFormatIsAMiss(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t, nil)

	codec, err := cache.NewCodec(nil)
	require.NoError(t, err)

	encoded, err := codec.Encode(testEntry(), false)
	require.NoError(t, err)

	// Bump the version byte, as a newer pivot would have written. Offset 6 is
	// pkg/seal's version, immediately after the six-byte magic.
	encoded[6] = 99

	_, decodeErr := codec.Decode(encoded, false)
	assert.ErrorIs(t, decodeErr, cache.ErrUnsupportedVersion)

	// Through the store it is a miss rather than an error, so the request is
	// served from the backend instead of failing.
	key := testKey(t, "c", "/api/product")
	require.NoError(t, store.Put(ctx, key, testEntry(), time.Minute, false))

	_, found, err := store.Get(ctx, key, false)
	require.NoError(t, err)
	assert.True(t, found)
}

func TestCorruptEntryIsAMiss(t *testing.T) {
	t.Parallel()

	codec, err := cache.NewCodec(nil)
	require.NoError(t, err)

	for name, stored := range map[string][]byte{
		"empty":       {},
		"too short":   {1, 2, 3},
		"wrong magic": []byte("NOTACAxxxxxxxxxxxxxx"),
		"truncated":   append([]byte("NTRYCA"), 1, 0, 0xff),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := codec.Decode(stored, false)
			assert.Error(t, err)
		})
	}
}

// A field claiming more bytes than are present must be refused rather than
// used to index past the end of the buffer.
func TestDecodeRejectsALyingLength(t *testing.T) {
	t.Parallel()

	codec, err := cache.NewCodec(nil)
	require.NoError(t, err)

	encoded, err := codec.Encode(testEntry(), false)
	require.NoError(t, err)

	// Chop the body off, leaving its declared length in place.
	_, err = codec.Decode(encoded[:len(encoded)-5], false)
	assert.ErrorIs(t, err, cache.ErrNotAnEntry)
}

func TestTTLExpiry(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t, nil)
	key := testKey(t, "c", "/api/product")

	require.NoError(t, store.Put(ctx, key, testEntry(), kv.TTLGranularity, false))

	_, found, err := store.Get(ctx, key, false)
	require.NoError(t, err)
	require.True(t, found)

	time.Sleep(kv.TTLGranularity + kv.TTLGranularity + 500*time.Millisecond)

	_, found, err = store.Get(ctx, key, false)
	require.NoError(t, err)
	assert.False(t, found, "a cached entry must not outlive its TTL")
}

func TestZeroTTLStoresNothing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t, nil)
	key := testKey(t, "c", "/api/product")

	require.NoError(t, store.Put(ctx, key, testEntry(), 0, false))

	_, found, err := store.Get(ctx, key, false)
	require.NoError(t, err)
	assert.False(t, found)
}

func TestPurgeAndCount(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newStore(t, nil)

	for _, path := range []string{"/api/a", "/api/b", "/api/c"} {
		require.NoError(t, store.Put(ctx, testKey(t, "c", path), testEntry(), time.Minute, false))
	}

	count, err := store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	removed, err := store.Purge(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, removed)

	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count)
}

func TestAge(t *testing.T) {
	t.Parallel()

	now := time.Now()

	asrt := assert.New(t)
	asrt.Equal(time.Minute, cache.Entry{StoredAt: now.Add(-time.Minute)}.Age(now))
	asrt.Zero(cache.Entry{}.Age(now), "an entry with no store time has no age")

	// A replica whose clock is behind the one that wrote the entry. Zero
	// rather than a negative age, which HTTP cannot express.
	asrt.Zero(cache.Entry{StoredAt: now.Add(time.Minute)}.Age(now))
}
