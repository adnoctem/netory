package kv

import "time"

// TTLGranularity is the coarsest resolution any implementation guarantees for
// an expiring key.
//
// Badger stores an entry's expiry as whole Unix seconds, so it cannot express
// anything finer. A TTL is therefore specified as a *lower* bound: a key lives
// at least the requested duration and at most one TTLGranularity longer. That
// direction is deliberate - an access token or a cache entry that outlives its
// TTL by a fraction of a second is harmless, while one that expires early is a
// spurious 401 or a cache miss storm.
//
// The practical consequence is that a sub-second TTL buys no sub-second
// precision. Nothing in the three services needs one: pivot's cache TTLs are
// minutes and its token lifetimes are longer still.
const TTLGranularity = time.Second

// SetOptions is the resolved per-write configuration.
type SetOptions struct {
	// TTL expires the key after the given duration. Zero means no expiry.
	TTL time.Duration
}

// SetOption configures a single write.
type SetOption func(*SetOptions)

// WithTTL expires the written key after d. A zero or negative d is treated as
// no expiry, so a caller computing a TTL from configuration cannot accidentally
// write a key that vanishes immediately.
//
// TTL is what pivot's hashed access tokens, rate-limit counters and cached
// responses are built on, and what bounds protean's address-history growth.
func WithTTL(d time.Duration) SetOption {
	return func(o *SetOptions) {
		if d > 0 {
			o.TTL = d
		}
	}
}

// ResolveSetOptions applies opts over the zero SetOptions. Implementations call
// this so that option semantics - notably the treatment of a non-positive TTL -
// are identical across backends instead of reimplemented per store.
func ResolveSetOptions(opts ...SetOption) SetOptions {
	var o SetOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	return o
}

// ExpiresAt resolves a TTL to an absolute expiry that is never earlier than
// now+ttl, compensating for backends that can only store whole seconds. It
// returns the zero Time when ttl is non-positive, meaning no expiry.
//
// Both implementations call this rather than each computing an expiry of their
// own, which is what keeps "a key lives at least its TTL" true on Badger -
// whose Entry.WithTTL truncates now+ttl to a whole second and so can mark a
// 150ms TTL as already expired before the write even returns.
func ExpiresAt(now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}

	// Truncation can lose just under one granularity unit, so add one unit
	// back. The result rounds the expiry up, never down.
	return now.Add(ttl).Truncate(TTLGranularity).Add(TTLGranularity)
}
