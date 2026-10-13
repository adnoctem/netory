// Package kv is the key-value contract shared by protean, signpost and pivot.
// It defines the Store interface and nothing that depends on a particular
// backend: the Badger implementation lives in pkg/kv/badgerkv and the Valkey
// implementation in pkg/kv/valkeykv, so a binary links only the client it
// actually uses.
//
// # Namespaces are arguments, never state
//
// The namespace is a parameter on every operation. A mutable "current
// namespace" set before each write - the design of gopskit's pkg/kv - lets two
// goroutines running "set namespace, then write" interleave and write into
// each other's namespace, which is a correctness defect in any concurrent
// server.
//
// There is therefore no current namespace to move. Callers either pass the
// namespace per call or bind one into an immutable Handle. No global mutex is
// needed either: Badger is safe for concurrent use and does its own conflict
// detection.
//
// # What implementations must agree on
//
// Store is implemented over two stores with meaningfully different primitives,
// so the contract is spelled out rather than left to whichever backend was
// written first:
//
//   - A missing key is ErrNotFound from Get, and (false, nil) from Has. Has
//     reports key existence, not value length - a key stored with an empty
//     value exists.
//   - Delete is idempotent. Removing an absent key is not an error.
//   - Keys and Scan return entries in unspecified order. Badger iterates in
//     key order and Valkey's SCAN does not, so a caller that needs ordering
//     sorts for itself.
//   - Increment treats the stored value as a decimal ASCII integer so Valkey
//     can use INCRBY natively and Badger a conflict-retrying transaction. An
//     absent key counts as zero; a value that is not a decimal integer is
//     ErrNotAnInteger.
//   - A zero TTL means no expiry. A TTL that has already elapsed makes the key
//     immediately absent rather than erroring.
//
// pkg/kv/kvtest holds a conformance suite asserting all of the above. Every
// implementation runs it, which is what keeps the second one honest.
package kv

import "context"

// Entry is one key-value pair as yielded by Scan. Key is relative to the
// namespace: the physical key the backend stores is an implementation detail
// and never appears in this package's API.
type Entry struct {
	Key   string
	Value []byte
}

// Store is a namespaced key-value store.
//
// Note what is absent. gopskit's Store interface exposes Path() string and
// Config() badger.Options, which no Valkey implementation can answer and which
// leak the backend into every caller's imports. Backend-specific accessors
// belong on the concrete type, so badgerkv.Store has Path and Options and this
// interface has neither.
//
// Implementations are safe for concurrent use by multiple goroutines.
type Store interface {
	// Get returns the value stored at key, or ErrNotFound if there is none.
	// The returned slice is owned by the caller and safe to retain.
	Get(ctx context.Context, ns, key string) ([]byte, error)

	// Set stores value at key, overwriting any previous value.
	Set(ctx context.Context, ns, key string, value []byte, opts ...SetOption) error

	// Has reports whether key exists. An absent key is (false, nil); only a
	// genuine backend failure produces a non-nil error.
	Has(ctx context.Context, ns, key string) (bool, error)

	// Delete removes key. Deleting an absent key succeeds.
	Delete(ctx context.Context, ns, key string) error

	// Keys returns the namespace-relative keys beginning with prefix, in
	// unspecified order. An empty prefix matches every key in the namespace.
	//
	// This walks the namespace, which is cheap on Badger and a full keyspace
	// scan on Valkey. It belongs in administrative paths - `host list`,
	// `bundle list`, draining the outbox - not on a per-request path.
	Keys(ctx context.Context, ns, prefix string) ([]string, error)

	// Scan calls fn for every entry beginning with prefix, in unspecified
	// order. Scan stops and returns fn's error, except for ErrStopIteration,
	// which stops the scan and returns nil.
	//
	// The Entry passed to fn is only valid for the duration of the call: an
	// implementation may reuse its buffers between iterations. Retain the value
	// by copying it.
	Scan(ctx context.Context, ns, prefix string, fn func(Entry) error) error

	// SetIfAbsent stores value at key only if the key does not exist, and
	// reports whether it wrote. It is the create-exclusively primitive behind
	// signpost's unique release versions and pivot's token issuance.
	SetIfAbsent(ctx context.Context, ns, key string, value []byte, opts ...SetOption) (bool, error)

	// CompareAndSwap replaces the value at key with value, but only if the
	// current value equals expected, and reports whether it wrote.
	//
	// The key must already exist: an absent key is (false, nil), never an
	// implicit create. Use SetIfAbsent for that, so the two primitives stay
	// non-overlapping.
	CompareAndSwap(ctx context.Context, ns, key string, expected, value []byte, opts ...SetOption) (bool, error)

	// Increment adds delta to the decimal ASCII integer stored at key and
	// returns the new value. An absent key counts as zero. A stored value that
	// is not a decimal integer, or an operation that would overflow int64, is
	// ErrNotAnInteger.
	Increment(ctx context.Context, ns, key string, delta int64, opts ...SetOption) (int64, error)

	// Close releases the store. Operations after Close return ErrClosed.
	Close() error
}
