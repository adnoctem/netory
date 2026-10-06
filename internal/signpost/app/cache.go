package app

import "sync"

// DefaultCacheBytes is how much script content is held in memory.
//
// Small on purpose. signpost serves a handful of install scripts that are tens
// of kilobytes each, so 32 MiB holds every hot path many times over, and a
// budget this size cannot become the reason the process is killed.
const DefaultCacheBytes int64 = 32 << 20

// contentCache keeps served bytes in memory, keyed by digest.
//
// Keyed by digest rather than by path, which makes it correct for free: the
// bytes under a digest can never be different bytes, so a cached entry can
// never become stale and a publish needs no invalidation. Two releases sharing
// an identical script share one entry.
//
// It also removes a per-request SHA-256. Storage.Get verifies every read
// against its digest, which is the right thing for the first read and a lever
// an anonymous client could pull repeatedly; verifying once on insert keeps
// the guarantee and drops the cost.
type contentCache struct {
	mu sync.Mutex

	// entries maps a digest to its bytes.
	entries map[string][]byte

	// order is insertion order, used for eviction.
	order []string

	// bytes is the current total, and budget the limit.
	bytes  int64
	budget int64
}

// newContentCache returns a cache with the given byte budget. A budget of zero
// or less disables caching entirely rather than meaning "unbounded" - a cache
// turned off by configuration must not turn into one that never evicts.
func newContentCache(budget int64) *contentCache {
	return &contentCache{
		entries: map[string][]byte{},
		budget:  budget,
	}
}

// get returns cached bytes.
func (c *contentCache) get(digest string) ([]byte, bool) {
	if c.budget <= 0 {
		return nil, false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	content, ok := c.entries[digest]

	return content, ok
}

// put caches bytes, evicting in insertion order until the budget is met.
//
// FIFO rather than LRU. With a working set this much smaller than the budget
// the policy almost never runs, and a policy that never runs is better off
// being one that is obviously correct than one that is clever.
func (c *contentCache) put(digest string, content []byte) {
	if c.budget <= 0 || int64(len(content)) > c.budget {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[digest]; exists {
		return
	}

	c.entries[digest] = content
	c.order = append(c.order, digest)
	c.bytes += int64(len(content))

	for c.bytes > c.budget && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]

		if evicted, ok := c.entries[oldest]; ok {
			c.bytes -= int64(len(evicted))
			delete(c.entries, oldest)
		}
	}
}

// forget drops entries for a set of digests, used when a release is removed.
//
// Not required for correctness - a digest's bytes are its bytes whether the
// release still exists or not - but holding the content of a deleted release
// in memory would make `bundle remove` look like it had not worked to anyone
// watching the process's footprint.
func (c *contentCache) forget(digests []string) {
	if len(digests) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	drop := make(map[string]bool, len(digests))
	for _, digest := range digests {
		drop[digest] = true
	}

	kept := c.order[:0]
	for _, digest := range c.order {
		if !drop[digest] {
			kept = append(kept, digest)

			continue
		}

		if content, ok := c.entries[digest]; ok {
			c.bytes -= int64(len(content))
			delete(c.entries, digest)
		}
	}

	c.order = kept
}

// stats reports the cache's occupancy, for the admin API.
func (c *contentCache) stats() (entries int, bytes, budget int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries), c.bytes, c.budget
}
