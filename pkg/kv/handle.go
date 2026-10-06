package kv

import "context"

// Handle binds a Store to one namespace.
//
// It is an immutable value with no setter, which is the entire point. gopskit
// offers the same ergonomics through SetNamespace on a shared *Database, so
// "use namespace X for a while" is a mutation other goroutines observe. Here
// the namespace is fixed when the Handle is created and a second namespace
// means a second Handle, so there is nothing to race on. Handles are cheap to
// copy and safe to share.
//
// Services wire their handles once at startup:
//
//	hosts, err := kv.In(store, "hosts")
//	if err != nil {
//	    return fmt.Errorf("hosts namespace: %w", err)
//	}
type Handle struct {
	store Store
	ns    string
}

// In binds store to ns. The namespace is validated here so that a malformed
// one fails at wiring time, where there is a single error path, rather than on
// the first request that happens to use it.
func In(store Store, ns string) (Handle, error) {
	if store == nil {
		return Handle{}, ErrClosed
	}

	if err := ValidateNamespace(ns); err != nil {
		return Handle{}, err
	}

	return Handle{store: store, ns: ns}, nil
}

// Namespace returns the namespace this Handle is bound to.
func (h Handle) Namespace() string { return h.ns }

// Store returns the underlying Store, for the rare caller that needs to reach
// a second namespace through the same connection.
func (h Handle) Store() Store { return h.store }

// Get returns the value stored at key within the Handle's namespace.
func (h Handle) Get(ctx context.Context, key string) ([]byte, error) {
	return h.store.Get(ctx, h.ns, key)
}

// Set stores value at key within the Handle's namespace.
func (h Handle) Set(ctx context.Context, key string, value []byte, opts ...SetOption) error {
	return h.store.Set(ctx, h.ns, key, value, opts...)
}

// Has reports whether key exists within the Handle's namespace.
func (h Handle) Has(ctx context.Context, key string) (bool, error) {
	return h.store.Has(ctx, h.ns, key)
}

// Delete removes key from the Handle's namespace.
func (h Handle) Delete(ctx context.Context, key string) error {
	return h.store.Delete(ctx, h.ns, key)
}

// Keys returns the keys in the Handle's namespace beginning with prefix.
func (h Handle) Keys(ctx context.Context, prefix string) ([]string, error) {
	return h.store.Keys(ctx, h.ns, prefix)
}

// Scan calls fn for every entry in the Handle's namespace beginning with prefix.
func (h Handle) Scan(ctx context.Context, prefix string, fn func(Entry) error) error {
	return h.store.Scan(ctx, h.ns, prefix, fn)
}

// SetIfAbsent stores value at key only if it does not already exist.
func (h Handle) SetIfAbsent(ctx context.Context, key string, value []byte, opts ...SetOption) (bool, error) {
	return h.store.SetIfAbsent(ctx, h.ns, key, value, opts...)
}

// CompareAndSwap replaces the value at key only if it currently equals expected.
func (h Handle) CompareAndSwap(ctx context.Context, key string, expected, value []byte, opts ...SetOption) (bool, error) {
	return h.store.CompareAndSwap(ctx, h.ns, key, expected, value, opts...)
}

// Increment adds delta to the counter at key and returns the new value.
func (h Handle) Increment(ctx context.Context, key string, delta int64, opts ...SetOption) (int64, error) {
	return h.store.Increment(ctx, h.ns, key, delta, opts...)
}
