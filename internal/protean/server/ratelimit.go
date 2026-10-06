package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/adnoctem/netory/pkg/kv"
)

// Limiter is a fixed-window rate limiter over the key-value store.
//
// Fixed window rather than a sliding one or a token bucket: the counter is a
// single Increment with a TTL, which the store already provides atomically, and
// the thing being limited is a router that updates every few minutes. The
// well-known weakness of a fixed window - up to twice the limit across a
// boundary - does not matter when the limit exists to catch a misconfigured
// client and to slow token guessing, rather than to meter a paid API.
//
// It is persistent rather than in-memory on purpose: protean is a single
// process, but a restart must not hand an attacker a fresh budget, and a
// restart loop is exactly what a determined one would try.
type Limiter struct {
	store kv.Handle
}

// NewLimiter returns a limiter counting in the given namespace.
func NewLimiter(store kv.Handle) *Limiter { return &Limiter{store: store} }

// Decision is the outcome of a limit check.
type Decision struct {
	// Allowed reports whether the request may proceed.
	Allowed bool

	// Count is the number of requests seen in the current window, including
	// this one.
	Count int64

	// Limit is the configured ceiling.
	Limit int

	// RetryAfter is how long until the window rolls over. It is what the
	// endpoint puts in a Retry-After header, so a well-behaved client backs
	// off instead of hammering.
	RetryAfter time.Duration
}

// Allow records a request against a key and reports whether it is permitted.
//
// A limit of zero or less disables the check, which is how an operator turns it
// off. The window is bucketed by wall-clock time so every process agrees on
// where a window starts without coordinating - which matters for the Valkey
// implementation pivot will use, where several replicas share the counters.
func (l *Limiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (Decision, error) {
	if limit <= 0 {
		return Decision{Allowed: true, Limit: limit}, nil
	}

	if window <= 0 {
		window = time.Hour
	}

	now := time.Now()
	bucket := now.UnixNano() / int64(window)
	counterKey := fmt.Sprintf("%s/%d", sanitizeKey(key), bucket)

	// The TTL is two windows, not one. A key written at the very end of its
	// window would otherwise expire almost immediately - kv TTLs are honoured
	// to one second and are a lower bound - and the counter would reset early.
	// Expiring late costs nothing: the bucket in the key already makes the
	// stale counter unreachable.
	count, err := l.store.Increment(ctx, counterKey, 1, kv.WithTTL(2*window))
	if err != nil {
		return Decision{}, fmt.Errorf("rate limit %q: %w", key, err)
	}

	// Time until this bucket ends.
	bucketEnd := time.Unix(0, (bucket+1)*int64(window))
	retryAfter := time.Until(bucketEnd)
	if retryAfter < time.Second {
		retryAfter = time.Second
	}

	return Decision{
		Allowed:    count <= int64(limit),
		Count:      count,
		Limit:      limit,
		RetryAfter: retryAfter,
	}, nil
}

// Reset clears a key's counters, for `host` administration and for tests.
func (l *Limiter) Reset(ctx context.Context, key string) error {
	prefix := sanitizeKey(key) + "/"

	keys, err := l.store.Keys(ctx, prefix)
	if err != nil {
		return fmt.Errorf("find rate limit counters for %q: %w", key, err)
	}

	for _, k := range keys {
		if err := l.store.Delete(ctx, k); err != nil {
			return fmt.Errorf("reset rate limit counter %q: %w", k, err)
		}
	}

	return nil
}

// sanitizeKey makes a limiter key safe to store.
//
// The key is built from a hostname or a source address, both of which come from
// the request. kv already rejects a NUL byte, but a "/" would make the bucket
// suffix ambiguous and let one key's counters be read as another's - so the
// separator is escaped rather than merely hoped to be absent.
func sanitizeKey(key string) string {
	key = strings.ReplaceAll(key, "%", "%25")
	key = strings.ReplaceAll(key, "/", "%2F")

	// Bound it, because kv caps a key's length and a hostname arrives from the
	// network. Truncating is safe: two distinct over-long keys colliding would
	// share a rate-limit budget, which is conservative rather than permissive.
	const maxKeyLen = 512
	if len(key) > maxKeyLen {
		key = key[:maxKeyLen]
	}

	return key
}

// HostKey is the limiter key for a host's updates.
func HostKey(host string) string { return "host/" + host }

// SourceKey is the limiter key for a source address's requests.
func SourceKey(source string) string { return "source/" + source }

// FailureKey is the limiter key counting authentication failures, which is what
// the auth.failed threshold is measured against.
func FailureKey(subject string) string { return "authfail/" + subject }
