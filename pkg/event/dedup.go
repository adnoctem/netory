package event

import (
	"sync"
	"time"
)

// maxDedupEntries bounds the deduplication table. The key space is
// type+subject, which is bounded by the number of configured hosts, releases or
// clients in normal operation - but an attacker hammering the update endpoint
// with made-up hostnames would generate auth.failed events with a fresh subject
// each time, and an unbounded map there is a memory leak with a remote trigger.
const maxDedupEntries = 10_000

// deduplicator collapses identical events that occur close together.
//
// protean section 8.2 requires that a flapping connection does not send one
// mail per address change, and signpost and pivot aggregate their denial and
// rate-limit events for the same reason. The identity used is the event's type
// and subject, not its whole content: the point is to suppress "host.updated
// for example.org" repeated five times in a minute, and those five events
// differ in their fields - the new address - which is precisely what should not
// make them count as distinct.
type deduplicator struct {
	window time.Duration

	mu     sync.Mutex
	recent map[string]time.Time
}

// newDeduplicator returns a deduplicator. A non-positive window disables
// deduplication entirely, which is what an operator who wants every event gets.
func newDeduplicator(window time.Duration) *deduplicator {
	return &deduplicator{window: window, recent: make(map[string]time.Time)}
}

// seen reports whether an identical event was already seen inside the window,
// recording this one if not.
func (d *deduplicator) seen(e Event, now time.Time) bool {
	if d.window <= 0 {
		return false
	}

	key := string(e.Type) + "\x00" + e.Subject

	d.mu.Lock()
	defer d.mu.Unlock()

	if last, ok := d.recent[key]; ok && now.Sub(last) < d.window {
		return true
	}

	// Sweep before inserting, so the map cannot grow past the cap. Sweeping
	// only on insert means the work is proportional to the event rate rather
	// than needing a timer of its own.
	if len(d.recent) >= maxDedupEntries {
		d.sweepLocked(now)
	}

	d.recent[key] = now

	return false
}

// sweepLocked drops entries older than the window, and if that was not enough,
// clears the table.
//
// Clearing is safe: losing deduplication state causes at worst a duplicate
// notification, which is the same failure mode the at-least-once outbox already
// has. Growing without bound would not be safe.
func (d *deduplicator) sweepLocked(now time.Time) {
	for key, last := range d.recent {
		if now.Sub(last) >= d.window {
			delete(d.recent, key)
		}
	}

	if len(d.recent) >= maxDedupEntries {
		d.recent = make(map[string]time.Time)
	}
}
