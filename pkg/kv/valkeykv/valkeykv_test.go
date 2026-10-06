package valkeykv_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valkey-io/valkey-go"

	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/kvtest"
	"github.com/adnoctem/netory/pkg/kv/valkeykv"
)

// AddressEnv names the Valkey these tests run against.
//
// A real server rather than a fake. The point of this package is that two
// stores with very different primitives satisfy one contract, and the
// interesting half of that - what SET NX returns on a existing key, whether
// SCAN yields an expired key, what INCRBY says about a non-numeric value - is
// the server's behaviour, not ours. A fake would assert that the fake agrees
// with the fake.
const AddressEnv = "VALKEY_TEST_ADDR"

// defaultAddress is where a locally run Valkey listens.
const defaultAddress = "127.0.0.1:6379"

// namespaceCounter keeps each store's namespaces distinct.
//
// Badger's tests get a fresh database per store from t.TempDir. There is no
// equivalent here: one Valkey serves the whole suite, and the conformance
// tests run in parallel and reuse a small set of namespace names. Prefixing
// every namespace with a per-store counter is what keeps two parallel
// subtests from seeing each other's keys - the same isolation, bought with a
// prefix instead of a directory.
var namespaceCounter atomic.Uint64

// address returns the Valkey address under test.
func address() string {
	if addr := strings.TrimSpace(os.Getenv(AddressEnv)); addr != "" {
		return addr
	}

	return defaultAddress
}

// requireValkey skips the test when no Valkey is reachable.
//
// Skipped rather than failed, with the reason spelled out: a developer with no
// Valkey running should not see a red suite for a store they are not working
// on. CI runs a Valkey service container, so the suite is not quietly skipped
// where it matters - which is the trade this makes, and the reason the skip
// message says how to get one.
func requireValkey(t *testing.T) string {
	t.Helper()

	addr := address()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Skipf("no Valkey reachable at %s (%v)\n"+
			"Start one with:  docker run --rm -p 6379:6379 valkey/valkey:8-alpine\n"+
			"Or point %s at an existing server.", addr, err, AddressEnv)
	}

	_ = conn.Close()

	return addr
}

// newStore returns a Store whose namespaces are unique to it, and clears its
// keys when the test ends.
func newStore(t *testing.T) kv.Store {
	t.Helper()

	addr := requireValkey(t)

	store, err := valkeykv.New(valkeykv.Options{
		Address:    []string{addr},
		ClientName: "netory-test",
	})
	require.NoError(t, err)

	prefix := fmt.Sprintf("t%d-", namespaceCounter.Add(1))

	t.Cleanup(func() {
		// Cleared through a fresh client: the store under test has usually
		// been closed by the test itself, and testClosed depends on that.
		flush(t, addr, prefix)
		_ = store.Close()
	})

	return &prefixed{Store: store, prefix: prefix}
}

// prefixed scopes every namespace to one test.
type prefixed struct {
	kv.Store

	prefix string
}

func (p *prefixed) ns(ns string) string {
	// An invalid namespace is passed through unchanged so the validation
	// conformance test still sees the value it supplied: prefixing "a/b"
	// would make it a different invalid namespace, and prefixing "" would
	// make it valid.
	if kv.ValidateNamespace(ns) != nil {
		return ns
	}

	return p.prefix + ns
}

func (p *prefixed) Get(ctx context.Context, ns, key string) ([]byte, error) {
	return p.Store.Get(ctx, p.ns(ns), key)
}

func (p *prefixed) Set(ctx context.Context, ns, key string, value []byte, opts ...kv.SetOption) error {
	return p.Store.Set(ctx, p.ns(ns), key, value, opts...)
}

func (p *prefixed) Has(ctx context.Context, ns, key string) (bool, error) {
	return p.Store.Has(ctx, p.ns(ns), key)
}

func (p *prefixed) Delete(ctx context.Context, ns, key string) error {
	return p.Store.Delete(ctx, p.ns(ns), key)
}

func (p *prefixed) Keys(ctx context.Context, ns, prefix string) ([]string, error) {
	return p.Store.Keys(ctx, p.ns(ns), prefix)
}

func (p *prefixed) Scan(ctx context.Context, ns, prefix string, fn func(kv.Entry) error) error {
	return p.Store.Scan(ctx, p.ns(ns), prefix, fn)
}

func (p *prefixed) SetIfAbsent(
	ctx context.Context, ns, key string, value []byte, opts ...kv.SetOption,
) (bool, error) {
	return p.Store.SetIfAbsent(ctx, p.ns(ns), key, value, opts...)
}

func (p *prefixed) CompareAndSwap(
	ctx context.Context, ns, key string, expected, value []byte, opts ...kv.SetOption,
) (bool, error) {
	return p.Store.CompareAndSwap(ctx, p.ns(ns), key, expected, value, opts...)
}

func (p *prefixed) Increment(
	ctx context.Context, ns, key string, delta int64, opts ...kv.SetOption,
) (int64, error) {
	return p.Store.Increment(ctx, p.ns(ns), key, delta, opts...)
}

// flush removes every key a test created.
func flush(t *testing.T, addr, prefix string) {
	t.Helper()

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  []string{addr},
		DisableCache: true,
	})
	if err != nil {
		t.Logf("could not connect to clean up %s*: %v", prefix, err)

		return
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var cursor uint64

	for {
		entry, err := client.Do(ctx, client.B().Scan().
			Cursor(cursor).Match(prefix+"*").Count(512).Build()).AsScanEntry()
		if err != nil {
			t.Logf("could not scan to clean up %s*: %v", prefix, err)

			return
		}

		if len(entry.Elements) > 0 {
			if err := client.Do(ctx, client.B().Del().Key(entry.Elements...).Build()).Error(); err != nil {
				t.Logf("could not delete %d keys for %s*: %v", len(entry.Elements), prefix, err)
			}
		}

		cursor = entry.Cursor
		if cursor == 0 {
			return
		}
	}
}

// TestConformance is the acceptance criterion pivot §10.9 names: the Valkey
// store is a kv.Store exactly insofar as it passes the same suite the Badger
// store passes.
func TestConformance(t *testing.T) {
	t.Parallel()

	kvtest.Suite(t, newStore)
}

func TestNewRejectsABadConfiguration(t *testing.T) {
	t.Parallel()

	_, err := valkeykv.New(valkeykv.Options{})
	assert.Error(t, err, "an address is required")

	_, err = valkeykv.New(valkeykv.Options{Address: []string{"  "}})
	assert.Error(t, err, "a blank address is not an address")
}

// A Store given a client it did not create must not close it: the client may
// be shared, and closing a connection pool out from under its owner is not
// this store's decision.
func TestCloseLeavesABorrowedClientOpen(t *testing.T) {
	t.Parallel()

	addr := requireValkey(t)
	ctx := context.Background()

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  []string{addr},
		DisableCache: true,
	})
	require.NoError(t, err)
	defer client.Close()

	store, err := valkeykv.New(valkeykv.Options{Client: client})
	require.NoError(t, err)

	require.NoError(t, store.Close())

	// The store refuses further work, and the client is still usable.
	_, err = store.Get(ctx, "ns", "key")
	assert.ErrorIs(t, err, kv.ErrClosed)

	assert.NoError(t, client.Do(ctx, client.B().Ping().Build()).Error())
}

func TestPing(t *testing.T) {
	t.Parallel()

	addr := requireValkey(t)
	ctx := context.Background()

	store, err := valkeykv.New(valkeykv.Options{Address: []string{addr}})
	require.NoError(t, err)

	require.NoError(t, store.Ping(ctx))
	require.NoError(t, store.Close())

	assert.ErrorIs(t, store.Ping(ctx), kv.ErrClosed)
}

// A key may contain glob metacharacters - kv.ValidateKey allows anything but
// NUL - so the SCAN pattern has to escape them. Unescaped, "rule[1]" would be
// read as a character class and a prefix containing '*' would silently widen
// the scan to keys the caller never asked for.
func TestScanEscapesGlobMetacharacters(t *testing.T) {
	t.Parallel()

	ctx, store := context.Background(), newStore(t)

	keys := []string{
		"rule[1]",
		"rule[2]",
		"rule*wild",
		"rule?one",
		"rule\\back",
		"rulePlain",
	}

	for _, key := range keys {
		require.NoError(t, store.Set(ctx, "globs", key, []byte("v")))
	}

	// Each literal prefix must match only the keys that literally start with
	// it, never the ones a glob would have caught.
	for prefix, want := range map[string][]string{
		"rule[1]":   {"rule[1]"},
		"rule*":     {"rule*wild"},
		"rule?":     {"rule?one"},
		"rule\\":    {"rule\\back"},
		"rulePlain": {"rulePlain"},
	} {
		found, err := store.Keys(ctx, "globs", prefix)
		require.NoError(t, err, prefix)
		assert.ElementsMatch(t, want, found, "prefix %q", prefix)
	}

	// And the empty prefix still matches the whole namespace.
	all, err := store.Keys(ctx, "globs", "")
	require.NoError(t, err)
	assert.ElementsMatch(t, keys, all)
}

// A namespace must not be able to see a neighbour whose name it prefixes.
// "rate" and "ratelimit" are both real pivot namespaces, and a scan of the
// first that returned the second's keys would be a rate limiter counting the
// wrong things.
func TestNamespacePrefixIsNotAPrefixMatch(t *testing.T) {
	t.Parallel()

	ctx, store := context.Background(), newStore(t)

	require.NoError(t, store.Set(ctx, "rate", "a", []byte("1")))
	require.NoError(t, store.Set(ctx, "ratelimit", "b", []byte("2")))

	rate, err := store.Keys(ctx, "rate", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, rate)

	limit, err := store.Keys(ctx, "ratelimit", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"b"}, limit)
}

// Values are opaque bytes, not strings. A credential ciphertext or a gob blob
// contains NULs and invalid UTF-8, and all of it has to survive the Lua
// scripts as well as a plain SET.
func TestBinaryValuesSurviveEveryWritePath(t *testing.T) {
	t.Parallel()

	ctx, store := context.Background(), newStore(t)

	binary := []byte{0x00, 0xff, 0xfe, '\n', '\r', 0x80, 0x00, 'a'}
	other := []byte{0x01, 0x00, 0x02}

	require.NoError(t, store.Set(ctx, "bin", "set", binary))

	got, err := store.Get(ctx, "bin", "set")
	require.NoError(t, err)
	assert.Equal(t, binary, got)

	wrote, err := store.SetIfAbsent(ctx, "bin", "nx", binary)
	require.NoError(t, err)
	require.True(t, wrote)

	got, err = store.Get(ctx, "bin", "nx")
	require.NoError(t, err)
	assert.Equal(t, binary, got)

	// The compare side of a CAS goes through Lua as an argument, so a binary
	// expected value is the case most likely to break.
	swapped, err := store.CompareAndSwap(ctx, "bin", "nx", binary, other)
	require.NoError(t, err)
	assert.True(t, swapped, "a binary expected value must compare equal to itself")

	got, err = store.Get(ctx, "bin", "nx")
	require.NoError(t, err)
	assert.Equal(t, other, got)

	// And a near-miss must not swap.
	swapped, err = store.CompareAndSwap(ctx, "bin", "nx", binary, []byte("x"))
	require.NoError(t, err)
	assert.False(t, swapped)
}

// A write with no TTL clears an expiry the key already had, because that is
// what Badger does - its entry simply carries no ExpiresAt. Without this the
// two stores would disagree about when a key disappears, which no conformance
// test covering a single backend would reveal.
func TestWriteWithoutTTLClearsAnExistingExpiry(t *testing.T) {
	t.Parallel()

	ctx, store := context.Background(), newStore(t)

	for name, rewrite := range map[string]func() error{
		"Set": func() error {
			return store.Set(ctx, "ttl", "set", []byte("second"))
		},
		"CompareAndSwap": func() error {
			_, err := store.CompareAndSwap(ctx, "ttl", "cas", []byte("first"), []byte("second"))

			return err
		},
		"Increment": func() error {
			_, err := store.Increment(ctx, "ttl", "incr", 1)

			return err
		},
	} {
		key := strings.ToLower(name)
		if name == "CompareAndSwap" {
			key = "cas"
		}

		if name == "Increment" {
			key = "incr"
		}

		seed := []byte("first")
		if name == "Increment" {
			seed = []byte("1")
		}

		require.NoError(t, store.Set(ctx, "ttl", key, seed, kv.WithTTL(kv.TTLGranularity)))
		require.NoError(t, rewrite(), name)

		// Well past the original TTL. The key must still be there, because
		// the rewrite carried no TTL of its own.
		time.Sleep(kv.TTLGranularity + kv.TTLGranularity + 500*time.Millisecond)

		has, err := store.Has(ctx, "ttl", key)
		require.NoError(t, err, name)
		assert.True(t, has, "%s with no TTL option must clear the previous expiry", name)
	}
}

// An increment with a TTL must apply it atomically with the increment. A
// counter whose expiry is set by a second command has a window in which it
// exists without one, and a crash there leaves a client rate-limited forever.
func TestIncrementAppliesItsTTL(t *testing.T) {
	t.Parallel()

	ctx, store := context.Background(), newStore(t)

	value, err := store.Increment(ctx, "ttl", "window", 1, kv.WithTTL(kv.TTLGranularity))
	require.NoError(t, err)
	assert.Equal(t, int64(1), value)

	time.Sleep(kv.TTLGranularity + kv.TTLGranularity + 500*time.Millisecond)

	has, err := store.Has(ctx, "ttl", "window")
	require.NoError(t, err)
	assert.False(t, has, "a counter written with a TTL must expire")

	// And the window starts again from zero rather than resuming.
	value, err = store.Increment(ctx, "ttl", "window", 1, kv.WithTTL(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), value)
}

// Valkey reports a non-numeric value and an overflow with the same class of
// error, and kv.ErrNotAnInteger covers both: from a caller's point of view
// "this is not a counter I can add to" is the same answer either way.
func TestIncrementOverflowIsNotAnInteger(t *testing.T) {
	t.Parallel()

	ctx, store := context.Background(), newStore(t)

	_, err := store.Increment(ctx, "counters", "max", 9223372036854775807)
	require.NoError(t, err)

	_, err = store.Increment(ctx, "counters", "max", 1)
	assert.ErrorIs(t, err, kv.ErrNotAnInteger)
}

// A cancelled context must not reach the server, and must be reported as
// cancellation rather than as a transport failure.
func TestCancelledContext(t *testing.T) {
	t.Parallel()

	store := newStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := store.Get(ctx, "ns", "key")
	assert.ErrorIs(t, err, context.Canceled)

	assert.ErrorIs(t, store.Set(ctx, "ns", "key", []byte("v")), context.Canceled)

	_, err = store.Keys(ctx, "ns", "")
	assert.ErrorIs(t, err, context.Canceled)

	assert.ErrorIs(t,
		store.Scan(ctx, "ns", "", func(kv.Entry) error { return nil }),
		context.Canceled)
}

// Scan's callback error propagates, and kv.ErrStopIteration stops the walk
// cleanly. The conformance suite covers both; this covers them over enough
// keys to span more than one SCAN cursor step, which is where an early stop
// in a paged walk could go wrong.
func TestScanStopsEarlyAcrossCursorSteps(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	addr := requireValkey(t)

	store, err := valkeykv.New(valkeykv.Options{
		Address: []string{addr},

		// One key per step, so a 50-key namespace is 50 cursor steps.
		ScanCount: 1,
	})
	require.NoError(t, err)

	prefix := fmt.Sprintf("s%d-", namespaceCounter.Add(1))
	ns := prefix + "paged"

	t.Cleanup(func() {
		flush(t, addr, prefix)
		_ = store.Close()
	})

	for i := range 50 {
		require.NoError(t, store.Set(ctx, ns, fmt.Sprintf("k%02d", i), []byte("v")))
	}

	seen := 0
	require.NoError(t, store.Scan(ctx, ns, "", func(kv.Entry) error {
		seen++
		if seen == 3 {
			return kv.ErrStopIteration
		}

		return nil
	}))
	assert.Equal(t, 3, seen, "ErrStopIteration must stop the walk, not finish it")

	// A real error from the callback propagates unchanged.
	sentinel := errors.New("callback failed")

	err = store.Scan(ctx, ns, "", func(kv.Entry) error { return sentinel })
	assert.ErrorIs(t, err, sentinel)

	// And a full walk still sees everything.
	all, err := store.Keys(ctx, ns, "")
	require.NoError(t, err)
	assert.Len(t, all, 50)
}
