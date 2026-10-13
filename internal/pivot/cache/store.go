package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/log"
)

// Store reads and writes cache entries in Valkey.
type Store struct {
	handle kv.Handle
	codec  *Codec
	logger *log.Logger
	now    func() time.Time
}

// StoreOptions are the dependencies a Store needs.
type StoreOptions struct {
	// Handle is the cache namespace.
	Handle kv.Handle

	// Codec encodes entries and seals the ones a route marks encrypted.
	Codec *Codec

	// Logger receives the reasons entries are skipped or discarded.
	Logger *log.Logger

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// NewStore returns a cache over a namespace handle.
func NewStore(opts StoreOptions) (*Store, error) {
	if opts.Codec == nil {
		return nil, errors.New("cache: a codec is required")
	}

	if opts.Logger == nil {
		return nil, errors.New("cache: a logger is required")
	}

	store := &Store{
		handle: opts.Handle,
		codec:  opts.Codec,
		logger: opts.Logger,
		now:    opts.Now,
	}

	if store.now == nil {
		store.now = time.Now
	}

	return store, nil
}

// CanEncrypt reports whether the cache can seal entries.
func (s *Store) CanEncrypt() bool { return s.codec.CanEncrypt() }

// Get returns a cached entry.
//
// A miss is (Entry{}, false, nil). So is an entry this build cannot read - a
// corrupt value, one written by a newer pivot during a rolling deployment, or
// one stored in the clear for a route that now requires encryption. Treating
// those as misses rather than errors is the only sensible behaviour: the
// request can still be served from the backend, and failing it would turn a
// cache problem into an outage.
//
// requireEncryption comes from the route's encrypt flag.
func (s *Store) Get(ctx context.Context, key Key, requireEncryption bool) (Entry, bool, error) {
	stored, err := s.handle.Get(ctx, key.String())
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return Entry{}, false, nil
		}

		return Entry{}, false, fmt.Errorf("cache: read: %w", err)
	}

	entry, err := s.codec.Decode(stored, requireEncryption)
	if err != nil {
		// Logged rather than returned, and the key is not deleted: its TTL
		// will take it, and a replica racing to delete an entry another
		// replica is writing would be a cache that fights itself.
		s.logger.Warn("discarding a cache entry this build cannot read",
			"client", key.Client, "path", key.Path, "error", err)

		return Entry{}, false, nil
	}

	return entry, true, nil
}

// Put stores an entry for the given TTL.
//
// A failure to store is returned so the caller can log it, but the caller must
// not fail the request over it: the response is already in hand, and the only
// consequence of a missing cache entry is the next request going to the
// backend.
func (s *Store) Put(ctx context.Context, key Key, entry Entry, ttl time.Duration, encrypt bool) error {
	if ttl <= 0 {
		return nil
	}

	entry.StoredAt = s.now().UTC()

	encoded, err := s.codec.Encode(entry, encrypt)
	if err != nil {
		return err
	}

	if err := s.handle.Set(ctx, key.String(), encoded, kv.WithTTL(ttl)); err != nil {
		return fmt.Errorf("cache: store: %w", err)
	}

	return nil
}

// Delete removes one entry.
func (s *Store) Delete(ctx context.Context, key Key) error {
	if err := s.handle.Delete(ctx, key.String()); err != nil {
		return fmt.Errorf("cache: delete: %w", err)
	}

	return nil
}

// Purge removes every cached entry.
//
// This walks the namespace, which is a full keyspace scan on
// Valkey, so it belongs on an administrative path and nowhere near a request.
// It exists because an operator who has just narrowed a rule or fixed a
// shared-route mistake needs a way to make the cache stop serving what it
// cached under the old configuration.
func (s *Store) Purge(ctx context.Context) (int, error) {
	keys, err := s.handle.Keys(ctx, "")
	if err != nil {
		return 0, fmt.Errorf("cache: list entries: %w", err)
	}

	removed := 0

	for _, key := range keys {
		if err := s.handle.Delete(ctx, key); err != nil {
			return removed, fmt.Errorf("cache: delete %s: %w", key, err)
		}

		removed++
	}

	return removed, nil
}

// Count returns how many entries are cached, for `config view`.
func (s *Store) Count(ctx context.Context) (int, error) {
	keys, err := s.handle.Keys(ctx, "")
	if err != nil {
		return 0, fmt.Errorf("cache: count entries: %w", err)
	}

	return len(keys), nil
}
