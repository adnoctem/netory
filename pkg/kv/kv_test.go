package kv_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/adnoctem/netory/pkg/kv"
)

func TestValidateNamespace(t *testing.T) {
	asrt := assert.New(t)

	for _, ns := range []string{"hosts", "a", "outbox-pending", "v1.state", "token_hashes", "A0"} {
		asrt.NoError(kv.ValidateNamespace(ns), ns)
	}

	// '/' and ':' are excluded on purpose: badgerkv joins with '/' and the
	// Valkey implementation will join with ':', so forbidding both here is
	// what keeps a physical key unambiguous under either backend.
	for name, ns := range map[string]string{
		"empty":     "",
		"slash":     "hosts/inner",
		"colon":     "hosts:inner",
		"space":     "two words",
		"NUL":       "ho\x00sts",
		"non-ASCII": "hösts",
		"newline":   "hosts\n",
		"too long":  strings.Repeat("n", kv.MaxNamespaceLen+1),
	} {
		asrt.ErrorIs(kv.ValidateNamespace(ns), kv.ErrInvalidNamespace, name)
	}

	asrt.NoError(kv.ValidateNamespace(strings.Repeat("n", kv.MaxNamespaceLen)), "the limit itself is legal")
}

func TestValidateKey(t *testing.T) {
	asrt := assert.New(t)

	// Keys are hierarchical by design - Keys and Scan take a prefix, which
	// only means something if keys nest - so separators are legal here even
	// though they are not in a namespace.
	for _, key := range []string{
		"a",
		"host/example.org",
		"token:abcdef",
		"outbox/01HQ/attempt=3",
		"a key with spaces",
		"ünïcode",
	} {
		asrt.NoError(kv.ValidateKey(key), key)
	}

	for name, key := range map[string]string{
		"empty":    "",
		"NUL":      "ho\x00st",
		"too long": strings.Repeat("k", kv.MaxKeyLen+1),
	} {
		asrt.ErrorIs(kv.ValidateKey(key), kv.ErrInvalidKey, name)
	}

	asrt.NoError(kv.ValidateKey(strings.Repeat("k", kv.MaxKeyLen)), "the limit itself is legal")
}

func TestValidateAndValidatePrefixed(t *testing.T) {
	asrt := assert.New(t)

	asrt.NoError(kv.Validate("hosts", "example.org"))
	asrt.ErrorIs(kv.Validate("bad/ns", "example.org"), kv.ErrInvalidNamespace)
	asrt.ErrorIs(kv.Validate("hosts", ""), kv.ErrInvalidKey)

	// An empty prefix means "the whole namespace", so it has to be legal where
	// an empty key is not.
	asrt.NoError(kv.ValidatePrefixed("hosts", ""))
	asrt.NoError(kv.ValidatePrefixed("hosts", "host/"))
	asrt.ErrorIs(kv.ValidatePrefixed("bad:ns", ""), kv.ErrInvalidNamespace)
	asrt.ErrorIs(kv.ValidatePrefixed("hosts", "a\x00b"), kv.ErrInvalidKey)
}

// The namespace charset is the mechanism that makes the physical key
// unambiguous, so assert the property directly rather than trusting the
// charset list to stay correct by inspection.
func TestNamespaceCharsetExcludesEverySeparatorAnImplementationMightUse(t *testing.T) {
	asrt := assert.New(t)

	for _, sep := range []string{"/", ":", "\x00", "|", "\x01"} {
		asrt.ErrorIs(kv.ValidateNamespace("ns"+sep+"suffix"), kv.ErrInvalidNamespace,
			"separator %q must not be legal inside a namespace", sep)
	}
}

func TestResolveSetOptions(t *testing.T) {
	asrt := assert.New(t)

	asrt.Zero(kv.ResolveSetOptions().TTL, "the default is no expiry")
	asrt.Equal(time.Minute, kv.ResolveSetOptions(kv.WithTTL(time.Minute)).TTL)

	// A caller computing a TTL from configuration must not be able to write a
	// key that vanishes immediately, so non-positive durations mean no expiry.
	asrt.Zero(kv.ResolveSetOptions(kv.WithTTL(0)).TTL)
	asrt.Zero(kv.ResolveSetOptions(kv.WithTTL(-time.Hour)).TTL)

	// The last option wins, and a nil option is skipped rather than panicking
	// - the variadic comes from caller-assembled slices.
	asrt.Equal(time.Hour, kv.ResolveSetOptions(kv.WithTTL(time.Minute), nil, kv.WithTTL(time.Hour)).TTL)
}

func TestInValidatesNamespace(t *testing.T) {
	asrt := assert.New(t)

	// A malformed namespace fails at wiring time, where there is one error
	// path, rather than on the first request that happens to use it.
	_, err := kv.In(nil, "hosts")
	asrt.ErrorIs(err, kv.ErrClosed, "binding a nil Store must fail rather than defer the panic")

	var store kv.Store = stubStore{}

	h, err := kv.In(store, "hosts")
	asrt.NoError(err)
	asrt.Equal("hosts", h.Namespace())
	asrt.Equal(store, h.Store())

	_, err = kv.In(store, "bad/ns")
	asrt.ErrorIs(err, kv.ErrInvalidNamespace)
}

// stubStore satisfies kv.Store for the Handle wiring tests, which assert
// binding behaviour and never touch a backend. Behavioural assertions live in
// pkg/kv/kvtest and run against real implementations.
type stubStore struct{}

func (stubStore) Get(context.Context, string, string) ([]byte, error) { return nil, nil }

func (stubStore) Set(context.Context, string, string, []byte, ...kv.SetOption) error { return nil }

func (stubStore) Has(context.Context, string, string) (bool, error) { return false, nil }

func (stubStore) Delete(context.Context, string, string) error { return nil }

func (stubStore) Keys(context.Context, string, string) ([]string, error) { return nil, nil }

func (stubStore) Scan(context.Context, string, string, func(kv.Entry) error) error { return nil }

func (stubStore) SetIfAbsent(context.Context, string, string, []byte, ...kv.SetOption) (bool, error) {
	return false, nil
}

func (stubStore) CompareAndSwap(
	context.Context, string, string, []byte, []byte, ...kv.SetOption,
) (bool, error) {
	return false, nil
}

func (stubStore) Increment(context.Context, string, string, int64, ...kv.SetOption) (int64, error) {
	return 0, nil
}

func (stubStore) Close() error { return nil }

// ExpiresAt is what keeps "a key lives at least its TTL" true on a backend
// that can only store whole seconds. The direction of the rounding is the
// whole point, so assert it rather than the exact value.
func TestExpiresAtNeverRoundsDown(t *testing.T) {
	asrt := assert.New(t)

	asrt.True(kv.ExpiresAt(time.Now(), 0).IsZero(), "a zero TTL means no expiry")
	asrt.True(kv.ExpiresAt(time.Now(), -time.Hour).IsZero(), "a negative TTL means no expiry")

	// Sweep offsets across a whole second. Badger's own Entry.WithTTL fails
	// for some of these - a sub-second TTL set early in a second truncates to
	// an expiry that has already passed - which is exactly the bug this
	// function exists to avoid.
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for _, offset := range []time.Duration{
		0, time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond, 999 * time.Millisecond,
	} {
		now := base.Add(offset)

		for _, ttl := range []time.Duration{
			time.Millisecond, 150 * time.Millisecond, time.Second, 90 * time.Second, time.Hour,
		} {
			expiry := kv.ExpiresAt(now, ttl)
			asrt.False(expiry.Before(now.Add(ttl)),
				"offset %v ttl %v: expiry %v is earlier than requested %v", offset, ttl, expiry, now.Add(ttl))

			// And not unboundedly late, or a rate-limit window would drift.
			asrt.True(expiry.Before(now.Add(ttl).Add(2*kv.TTLGranularity)),
				"offset %v ttl %v: expiry %v is more than two granularity units late", offset, ttl, expiry)

			asrt.Equal(expiry, expiry.Truncate(kv.TTLGranularity),
				"the expiry must land on a granularity boundary a whole-second backend can store")
		}
	}
}
