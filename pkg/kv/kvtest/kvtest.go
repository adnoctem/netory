// Package kvtest is the conformance suite for kv.Store implementations.
//
// kv.Store is implemented over two stores with meaningfully different
// primitives - Badger transactions and Valkey commands - and the point of the
// interface is that protean, signpost and pivot cannot tell which one they are
// talking to. That only holds if both implementations agree on the awkward
// cases: whether an empty value counts as present, whether deleting an absent
// key is an error, what an Increment over a non-numeric value does.
//
// So those answers live here as executable assertions rather than in prose.
// Every implementation runs Suite; an implementation that does not pass it is
// not a kv.Store regardless of whether it compiles as one.
package kvtest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/kv"
)

// Factory opens a fresh, empty Store for one subtest. The implementation is
// responsible for registering its own t.Cleanup to release the store.
type Factory func(t *testing.T) kv.Store

// Namespaces used by the suite. Two distinct ones, because namespace isolation
// under concurrency is the defect this package exists to prevent regressing.
const (
	nsA = "alpha"
	nsB = "beta"
)

// Suite runs every conformance test against the Store that newStore produces.
func Suite(t *testing.T, newStore Factory) {
	t.Helper()

	for name, fn := range map[string]func(*testing.T, Factory){
		"GetMissing":            testGetMissing,
		"SetGetRoundTrip":       testSetGetRoundTrip,
		"SetOverwrites":         testSetOverwrites,
		"EmptyValueIsPresent":   testEmptyValueIsPresent,
		"Delete":                testDelete,
		"NamespaceIsolation":    testNamespaceIsolation,
		"Keys":                  testKeys,
		"Scan":                  testScan,
		"ScanStopIteration":     testScanStopIteration,
		"ScanPropagatesError":   testScanPropagatesError,
		"SetIfAbsent":           testSetIfAbsent,
		"CompareAndSwap":        testCompareAndSwap,
		"Increment":             testIncrement,
		"IncrementNotAnInteger": testIncrementNotAnInteger,
		"TTL":                   testTTL,
		"Validation":            testValidation,
		"Closed":                testClosed,
		"ConcurrentNamespaces":  testConcurrentNamespaces,
		"ConcurrentIncrement":   testConcurrentIncrement,
		"ConcurrentSetIfAbsent": testConcurrentSetIfAbsent,
		"ConcurrentHandles":     testConcurrentHandles,
	} {
		t.Run(name, func(t *testing.T) { fn(t, newStore) })
	}
}

func testGetMissing(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	_, err := store.Get(ctx, nsA, "absent")
	asrt.ErrorIs(err, kv.ErrNotFound, "a missing key must be kv.ErrNotFound, never a backend-specific error")

	has, err := store.Has(ctx, nsA, "absent")
	asrt.NoError(err, "Has must report a missing key as (false, nil), not as an error")
	asrt.False(has)
}

func testSetGetRoundTrip(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	require.NoError(t, store.Set(ctx, nsA, "greeting", []byte("hello")))

	got, err := store.Get(ctx, nsA, "greeting")
	asrt.NoError(err)
	asrt.Equal("hello", string(got))

	has, err := store.Has(ctx, nsA, "greeting")
	asrt.NoError(err)
	asrt.True(has)
}

func testSetOverwrites(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	require.NoError(t, store.Set(ctx, nsA, "key", []byte("first")))
	require.NoError(t, store.Set(ctx, nsA, "key", []byte("second")))

	got, err := store.Get(ctx, nsA, "key")
	asrt.NoError(err)
	asrt.Equal("second", string(got))
}

// A key stored with an empty value exists. gopskit's Has is `len(value) > 0`,
// which reports exactly this key as absent - a presence flag stored as an
// empty value would silently never be seen.
func testEmptyValueIsPresent(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	require.NoError(t, store.Set(ctx, nsA, "flag", []byte{}))

	has, err := store.Has(ctx, nsA, "flag")
	asrt.NoError(err)
	asrt.True(has, "a key stored with an empty value must still exist")

	got, err := store.Get(ctx, nsA, "flag")
	asrt.NoError(err)
	asrt.Empty(got)
}

func testDelete(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	require.NoError(t, store.Set(ctx, nsA, "key", []byte("value")))
	require.NoError(t, store.Delete(ctx, nsA, "key"))

	has, err := store.Has(ctx, nsA, "key")
	asrt.NoError(err)
	asrt.False(has)

	asrt.NoError(store.Delete(ctx, nsA, "key"), "Delete must be idempotent")
	asrt.NoError(store.Delete(ctx, nsA, "never-existed"), "deleting an absent key must succeed")
}

func testNamespaceIsolation(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	require.NoError(t, store.Set(ctx, nsA, "key", []byte("in-alpha")))
	require.NoError(t, store.Set(ctx, nsB, "key", []byte("in-beta")))

	a, err := store.Get(ctx, nsA, "key")
	asrt.NoError(err)
	asrt.Equal("in-alpha", string(a))

	b, err := store.Get(ctx, nsB, "key")
	asrt.NoError(err)
	asrt.Equal("in-beta", string(b))

	// Deleting in one namespace must not touch the other.
	require.NoError(t, store.Delete(ctx, nsA, "key"))

	has, err := store.Has(ctx, nsB, "key")
	asrt.NoError(err)
	asrt.True(has)
}

func testKeys(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	for _, k := range []string{"host/a.example", "host/b.example", "token/abc"} {
		require.NoError(t, store.Set(ctx, nsA, k, []byte("v")))
	}
	require.NoError(t, store.Set(ctx, nsB, "host/other.example", []byte("v")))

	// Keys and Scan document their order as unspecified, so every assertion
	// here sorts first rather than depending on one backend's iteration order.
	hosts, err := store.Keys(ctx, nsA, "host/")
	asrt.NoError(err)
	sort.Strings(hosts)
	asrt.Equal([]string{"host/a.example", "host/b.example"}, hosts)

	all, err := store.Keys(ctx, nsA, "")
	asrt.NoError(err)
	sort.Strings(all)
	asrt.Equal([]string{"host/a.example", "host/b.example", "token/abc"}, all,
		"an empty prefix must match the whole namespace and nothing outside it")

	none, err := store.Keys(ctx, nsA, "nothing/")
	asrt.NoError(err)
	asrt.Empty(none, "a prefix matching nothing is an empty result, not an error")
}

func testScan(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	want := map[string]string{"a": "1", "b": "2", "c": "3"}
	for k, v := range want {
		require.NoError(t, store.Set(ctx, nsA, k, []byte(v)))
	}
	require.NoError(t, store.Set(ctx, nsB, "a", []byte("other")))

	got := map[string]string{}
	err := store.Scan(ctx, nsA, "", func(e kv.Entry) error {
		// Copy the value: Scan documents the Entry as valid only for the
		// duration of the callback.
		got[e.Key] = string(e.Value)

		return nil
	})
	asrt.NoError(err)
	asrt.Equal(want, got, "Scan must yield its own namespace only")
}

func testScanStopIteration(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	for i := range 10 {
		require.NoError(t, store.Set(ctx, nsA, strconv.Itoa(i), []byte("v")))
	}

	seen := 0
	err := store.Scan(ctx, nsA, "", func(kv.Entry) error {
		seen++

		return kv.ErrStopIteration
	})
	asrt.NoError(err, "ErrStopIteration is a clean stop, not an error to propagate")
	asrt.Equal(1, seen)
}

func testScanPropagatesError(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	require.NoError(t, store.Set(ctx, nsA, "key", []byte("v")))

	sentinel := errors.New("callback failed")
	err := store.Scan(ctx, nsA, "", func(kv.Entry) error { return sentinel })
	asrt.ErrorIs(err, sentinel, "any error other than ErrStopIteration must reach the caller")
}

func testSetIfAbsent(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	wrote, err := store.SetIfAbsent(ctx, nsA, "release/1.4.0", []byte("first"))
	asrt.NoError(err)
	asrt.True(wrote)

	wrote, err = store.SetIfAbsent(ctx, nsA, "release/1.4.0", []byte("second"))
	asrt.NoError(err)
	asrt.False(wrote, "SetIfAbsent must not overwrite an existing key")

	got, err := store.Get(ctx, nsA, "release/1.4.0")
	asrt.NoError(err)
	asrt.Equal("first", string(got), "the existing value must be untouched")

	// An empty value still occupies the key, so a subsequent SetIfAbsent fails.
	_, err = store.SetIfAbsent(ctx, nsA, "empty", []byte{})
	asrt.NoError(err)

	wrote, err = store.SetIfAbsent(ctx, nsA, "empty", []byte("x"))
	asrt.NoError(err)
	asrt.False(wrote, "a key holding an empty value is still present")
}

func testCompareAndSwap(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	// An absent key is never an implicit create - that is SetIfAbsent's job,
	// and keeping the two non-overlapping is what makes either one meaningful.
	swapped, err := store.CompareAndSwap(ctx, nsA, "alias/latest", []byte("1.3.0"), []byte("1.4.0"))
	asrt.NoError(err)
	asrt.False(swapped)

	has, err := store.Has(ctx, nsA, "alias/latest")
	asrt.NoError(err)
	asrt.False(has, "a failed CompareAndSwap must not create the key")

	require.NoError(t, store.Set(ctx, nsA, "alias/latest", []byte("1.3.0")))

	swapped, err = store.CompareAndSwap(ctx, nsA, "alias/latest", []byte("1.2.0"), []byte("1.4.0"))
	asrt.NoError(err)
	asrt.False(swapped, "a mismatched expected value must not swap")

	got, err := store.Get(ctx, nsA, "alias/latest")
	asrt.NoError(err)
	asrt.Equal("1.3.0", string(got))

	swapped, err = store.CompareAndSwap(ctx, nsA, "alias/latest", []byte("1.3.0"), []byte("1.4.0"))
	asrt.NoError(err)
	asrt.True(swapped)

	got, err = store.Get(ctx, nsA, "alias/latest")
	asrt.NoError(err)
	asrt.Equal("1.4.0", string(got))
}

func testIncrement(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	n, err := store.Increment(ctx, nsA, "rate/client-1", 1)
	asrt.NoError(err)
	asrt.Equal(int64(1), n, "an absent counter starts at zero")

	n, err = store.Increment(ctx, nsA, "rate/client-1", 4)
	asrt.NoError(err)
	asrt.Equal(int64(5), n)

	n, err = store.Increment(ctx, nsA, "rate/client-1", -2)
	asrt.NoError(err)
	asrt.Equal(int64(3), n, "a negative delta must decrement")

	// The stored encoding is decimal ASCII, which is what lets Valkey use
	// INCRBY natively and keeps a counter readable with a plain Get.
	raw, err := store.Get(ctx, nsA, "rate/client-1")
	asrt.NoError(err)
	asrt.Equal("3", string(raw))

	// A counter written through Set must be readable by Increment.
	require.NoError(t, store.Set(ctx, nsA, "preset", []byte("41")))
	n, err = store.Increment(ctx, nsA, "preset", 1)
	asrt.NoError(err)
	asrt.Equal(int64(42), n)
}

func testIncrementNotAnInteger(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	require.NoError(t, store.Set(ctx, nsA, "text", []byte("not a number")))
	_, err := store.Increment(ctx, nsA, "text", 1)
	asrt.ErrorIs(err, kv.ErrNotAnInteger)

	require.NoError(t, store.Set(ctx, nsA, "max", []byte(strconv.FormatInt(math.MaxInt64, 10))))
	_, err = store.Increment(ctx, nsA, "max", 1)
	asrt.ErrorIs(err, kv.ErrNotAnInteger, "an increment that overflows int64 must be rejected, not wrapped")

	require.NoError(t, store.Set(ctx, nsA, "min", []byte(strconv.FormatInt(math.MinInt64, 10))))
	_, err = store.Increment(ctx, nsA, "min", -1)
	asrt.ErrorIs(err, kv.ErrNotAnInteger)
}

func testTTL(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	// The TTL has to be at least kv.TTLGranularity: Badger stores expiry as
	// whole Unix seconds, so nothing finer is expressible. kv.ExpiresAt rounds
	// up, which makes the requested duration a lower bound - hence the wait
	// below is longer than the TTL by a full granularity unit plus slack.
	const ttl = kv.TTLGranularity

	require.NoError(t, store.Set(ctx, nsA, "session", []byte("v"), kv.WithTTL(ttl)))
	require.NoError(t, store.Set(ctx, nsA, "permanent", []byte("v")))

	has, err := store.Has(ctx, nsA, "session")
	asrt.NoError(err)
	asrt.True(has, "a key must be present before its TTL elapses")

	time.Sleep(ttl + kv.TTLGranularity + 500*time.Millisecond)

	_, err = store.Get(ctx, nsA, "session")
	asrt.ErrorIs(err, kv.ErrNotFound, "an expired key must read as absent")

	has, err = store.Has(ctx, nsA, "session")
	asrt.NoError(err)
	asrt.False(has)

	// An expired key must also be gone from the listing operations, or
	// draining the outbox would keep rediscovering entries it cannot read.
	keys, err := store.Keys(ctx, nsA, "")
	asrt.NoError(err)
	asrt.Equal([]string{"permanent"}, keys, "Keys must not yield expired entries")

	var scanned []string
	asrt.NoError(store.Scan(ctx, nsA, "", func(e kv.Entry) error {
		scanned = append(scanned, e.Key)

		return nil
	}))
	asrt.Equal([]string{"permanent"}, scanned, "Scan must not yield expired entries")

	// A non-positive TTL means no expiry, so configuration that computes a
	// duration cannot accidentally write a key that vanishes at once.
	require.NoError(t, store.Set(ctx, nsA, "zero-ttl", []byte("v"), kv.WithTTL(0)))
	require.NoError(t, store.Set(ctx, nsA, "negative-ttl", []byte("v"), kv.WithTTL(-time.Hour)))

	for _, k := range []string{"zero-ttl", "negative-ttl"} {
		has, err := store.Has(ctx, nsA, k)
		asrt.NoError(err, k)
		asrt.True(has, "%s: a non-positive TTL must mean no expiry", k)
	}
}

func testValidation(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	badNamespaces := map[string]string{
		"empty":            "",
		"contains slash":   "a/b",
		"contains colon":   "a:b",
		"contains space":   "a b",
		"contains NUL":     "a\x00b",
		"too long":         strings.Repeat("n", kv.MaxNamespaceLen+1),
		"non-ASCII letter": "nämespace",
	}
	for name, ns := range badNamespaces {
		_, err := store.Get(ctx, ns, "key")
		asrt.ErrorIs(err, kv.ErrInvalidNamespace, "namespace %s", name)

		err = store.Set(ctx, ns, "key", []byte("v"))
		asrt.ErrorIs(err, kv.ErrInvalidNamespace, "namespace %s", name)

		// gopskit applies its key guard in Get, Set and Has but omits it in
		// Delete. Validation has to be symmetric or the asymmetry becomes the
		// bug.
		err = store.Delete(ctx, ns, "key")
		asrt.ErrorIs(err, kv.ErrInvalidNamespace, "namespace %s", name)
	}

	badKeys := map[string]string{
		"empty":        "",
		"contains NUL": "a\x00b",
		"too long":     strings.Repeat("k", kv.MaxKeyLen+1),
	}
	for name, key := range badKeys {
		_, err := store.Get(ctx, nsA, key)
		asrt.ErrorIs(err, kv.ErrInvalidKey, "key %s", name)

		err = store.Set(ctx, nsA, key, []byte("v"))
		asrt.ErrorIs(err, kv.ErrInvalidKey, "key %s", name)

		err = store.Delete(ctx, nsA, key)
		asrt.ErrorIs(err, kv.ErrInvalidKey, "key %s", name)

		_, err = store.Has(ctx, nsA, key)
		asrt.ErrorIs(err, kv.ErrInvalidKey, "key %s", name)
	}

	// Keys may contain separators - they have to, since prefix listing only
	// means anything for hierarchical keys. gopskit rejects any key with a
	// slash in it, and that rule does not survive the port.
	asrt.NoError(store.Set(ctx, nsA, "host/example.org", []byte("v")))
	asrt.NoError(store.Set(ctx, nsA, "outbox/01HQ/retry:3", []byte("v")))

	// An empty prefix is legal for the prefix-taking operations.
	_, err := store.Keys(ctx, nsA, "")
	asrt.NoError(err)
}

func testClosed(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	require.NoError(t, store.Set(ctx, nsA, "key", []byte("v")))
	require.NoError(t, store.Close())

	asrt.NoError(store.Close(), "Close must be idempotent")

	_, err := store.Get(ctx, nsA, "key")
	asrt.ErrorIs(err, kv.ErrClosed)

	asrt.ErrorIs(store.Set(ctx, nsA, "key", []byte("v")), kv.ErrClosed)
	asrt.ErrorIs(store.Delete(ctx, nsA, "key"), kv.ErrClosed)

	_, err = store.Has(ctx, nsA, "key")
	asrt.ErrorIs(err, kv.ErrClosed)

	_, err = store.Keys(ctx, nsA, "")
	asrt.ErrorIs(err, kv.ErrClosed)

	asrt.ErrorIs(store.Scan(ctx, nsA, "", func(kv.Entry) error { return nil }), kv.ErrClosed)

	_, err = store.SetIfAbsent(ctx, nsA, "key", []byte("v"))
	asrt.ErrorIs(err, kv.ErrClosed)

	_, err = store.CompareAndSwap(ctx, nsA, "key", []byte("v"), []byte("w"))
	asrt.ErrorIs(err, kv.ErrClosed)

	_, err = store.Increment(ctx, nsA, "counter", 1)
	asrt.ErrorIs(err, kv.ErrClosed)
}

// testConcurrentNamespaces guards against the namespace race a mutable
// current namespace allows.
//
// gopskit's kv keeps the active namespace in a mutable field and moves it with
// SetNamespace, so "write to alpha" is two steps - set the namespace, then
// write - that another goroutine can interleave. Two goroutines writing to two
// namespaces therefore race twice over: on the namespace field itself, which
// the race detector reports, and on the destination of the write, which shows
// up as a value appearing under the wrong namespace.
//
// Here the namespace is an argument, so there is no window between choosing it
// and using it. The assertion is that every key written to alpha holds alpha's
// value and every key written to beta holds beta's, with the two sides writing
// identical key sets concurrently so any crossover is visible.
func testConcurrentNamespaces(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	const (
		writersPerNamespace = 8
		keysPerWriter       = 64
	)

	// Both namespaces use the same key names deliberately: if a write ever
	// landed in the wrong namespace it would overwrite a real key rather than
	// create a harmlessly distinct one, which is what makes the crossover
	// detectable at all.
	key := func(writer, i int) string { return fmt.Sprintf("w%d/k%d", writer, i) }

	var wg sync.WaitGroup
	for _, ns := range []string{nsA, nsB} {
		for writer := range writersPerNamespace {
			wg.Add(1)
			go func(ns string, writer int) {
				defer wg.Done()

				for i := range keysPerWriter {
					if err := store.Set(ctx, ns, key(writer, i), []byte(ns)); err != nil {
						t.Errorf("Set(%s, %s): %v", ns, key(writer, i), err)

						return
					}
				}
			}(ns, writer)
		}
	}
	wg.Wait()

	for _, ns := range []string{nsA, nsB} {
		for writer := range writersPerNamespace {
			for i := range keysPerWriter {
				got, err := store.Get(ctx, ns, key(writer, i))
				if !asrt.NoError(err, "%s/%s", ns, key(writer, i)) {
					continue
				}

				asrt.Equal(ns, string(got),
					"%s/%s holds %q: a write crossed into the wrong namespace", ns, key(writer, i), got)
			}
		}
	}

	// Neither namespace may have grown keys the other wrote.
	for _, ns := range []string{nsA, nsB} {
		keys, err := store.Keys(ctx, ns, "")
		asrt.NoError(err)
		asrt.Len(keys, writersPerNamespace*keysPerWriter, "namespace %s has an unexpected key count", ns)
	}
}

// Concurrent Increment must lose no updates. This is the assertion behind
// pivot's per-client rate limiting: a counter that drops increments under
// contention silently raises every client's effective limit.
func testConcurrentIncrement(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	const (
		goroutines           = 8
		incrementsPerRoutine = 50
	)

	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for range incrementsPerRoutine {
				if _, err := store.Increment(ctx, nsA, "rate/shared", 1); err != nil {
					t.Errorf("Increment: %v", err)

					return
				}
			}
		}()
	}
	wg.Wait()

	raw, err := store.Get(ctx, nsA, "rate/shared")
	require.NoError(t, err)

	got, err := strconv.ParseInt(string(raw), 10, 64)
	asrt.NoError(err)
	asrt.Equal(int64(goroutines*incrementsPerRoutine), got, "concurrent increments must not be lost")
}

// Exactly one concurrent SetIfAbsent may win. This is what makes signpost's
// "release version unique per instance" rule enforceable rather than
// best-effort.
func testConcurrentSetIfAbsent(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	const goroutines = 8

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
	)
	for i := range goroutines {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			wrote, err := store.SetIfAbsent(ctx, nsA, "release/1.0.0", []byte(strconv.Itoa(i)))
			if err != nil {
				t.Errorf("SetIfAbsent: %v", err)

				return
			}

			if wrote {
				mu.Lock()
				winners++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	asrt.Equal(1, winners, "exactly one concurrent SetIfAbsent may report having written")
}

// Two Handles over one Store, used concurrently, must stay isolated. A Handle
// is the ergonomic replacement for SetNamespace, so this asserts that the
// replacement does not reintroduce what it replaced.
func testConcurrentHandles(t *testing.T, newStore Factory) {
	asrt := assert.New(t)
	ctx, store := context.Background(), newStore(t)

	alpha, err := kv.In(store, nsA)
	require.NoError(t, err)

	beta, err := kv.In(store, nsB)
	require.NoError(t, err)

	const iterations = 100

	var wg sync.WaitGroup
	for _, h := range []kv.Handle{alpha, beta} {
		wg.Add(1)
		go func(h kv.Handle) {
			defer wg.Done()

			for i := range iterations {
				key := strconv.Itoa(i)
				if err := h.Set(ctx, key, []byte(h.Namespace())); err != nil {
					t.Errorf("Set(%s/%s): %v", h.Namespace(), key, err)

					return
				}

				got, err := h.Get(ctx, key)
				if err != nil {
					t.Errorf("Get(%s/%s): %v", h.Namespace(), key, err)

					return
				}

				if string(got) != h.Namespace() {
					t.Errorf("%s/%s holds %q, want %q", h.Namespace(), key, got, h.Namespace())

					return
				}
			}
		}(h)
	}
	wg.Wait()

	asrt.Equal(nsA, alpha.Namespace(), "a Handle's namespace must be immutable")
	asrt.Equal(nsB, beta.Namespace())
}
