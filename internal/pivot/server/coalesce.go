package server

import (
	"context"
	"sync"
	"sync/atomic"
)

// Coalescer makes identical concurrent requests share one backend call (§4
// step 7, §7.1).
//
// Per replica and in memory, which is what §7.1 specifies. Coordinating it
// through Valkey would mean a round trip on the hot path to discover whether
// another replica happens to be making the same call right now, and the window
// in which that is true is the duration of one backend request.
//
// The key is the cache key, which is the important detail: that key already
// covers the client, the method, the normalized path, the canonical query and
// a hash of the body. Coalescing on anything coarser would let two customers
// share a response, so this reuses the one string that is already known to
// identify a request completely.
//
// Written rather than taken from golang.org/x/sync/singleflight, which does
// this and more - it is sixty lines, it needs no dependency sign-off, and the
// shared-result semantics below are ones worth being able to read.
type Coalescer struct {
	mu    sync.Mutex
	calls map[string]*call

	// shared counts how many requests were answered by somebody else's
	// backend call, which is the only way to see whether coalescing is doing
	// anything on a given deployment.
	shared atomic.Int64
}

// call is one in-flight backend request.
type call struct {
	done chan struct{}

	// value and err are the outcome, written once before done is closed and
	// read only after, so no lock is needed around them.
	value any
	err   error

	// waiters counts the callers sharing this call, for the metric.
	waiters atomic.Int64
}

// NewCoalescer returns an empty coalescer.
func NewCoalescer() *Coalescer {
	return &Coalescer{calls: map[string]*call{}}
}

// Result is what Do reports about one request.
type Result struct {
	// Value is the outcome of the backend call.
	Value any

	// Shared reports whether this caller waited for another's call rather
	// than making its own. It belongs in the audit record: a request that
	// never touched the backend took a different path through the pipeline,
	// and a latency figure without it is misleading.
	Shared bool
}

// Do runs fn unless an identical call is already in flight, in which case it
// waits for that one and returns its result.
//
// A caller whose context is cancelled while waiting stops waiting, but does
// not cancel the call it was waiting on - another caller may still want it,
// and the first caller's disconnection is not a reason to waste a backend
// request that is already in progress.
func (c *Coalescer) Do(ctx context.Context, key string, fn func() (any, error)) (Result, error) {
	c.mu.Lock()

	if existing, ok := c.calls[key]; ok {
		existing.waiters.Add(1)
		c.mu.Unlock()

		select {
		case <-existing.done:
			c.shared.Add(1)

			return Result{Value: existing.value, Shared: true}, existing.err
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	}

	current := &call{done: make(chan struct{})}
	c.calls[key] = current
	c.mu.Unlock()

	// The leader runs fn. Its own context is not consulted here: fn was built
	// by the caller and carries whatever deadline it should have, and the
	// followers are waiting on this result.
	current.value, current.err = fn()

	c.mu.Lock()
	// Deleted before the waiters are released, so a request arriving after
	// this one finishes starts a fresh call rather than joining a completed
	// one and getting a stale answer.
	delete(c.calls, key)
	c.mu.Unlock()

	close(current.done)

	return Result{Value: current.value}, current.err
}

// InFlight returns how many distinct calls are running, for `config view`.
func (c *Coalescer) InFlight() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.calls)
}

// Shared returns how many requests were answered by another's backend call.
func (c *Coalescer) Shared() int64 { return c.shared.Load() }
