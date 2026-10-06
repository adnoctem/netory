package server

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// DefaultBackendConcurrency is how many backend calls one replica makes at
// once.
//
// §7.1 is explicit that this is the mechanism which actually protects
// production, and equally explicit about its cost: it is enforced per replica,
// so the effective ceiling is this value multiplied by the replica count.
// Scaling pivot out therefore raises the load the backend can see unless this
// is lowered to match, which is why the startup log states the figure and the
// multiplication rather than leaving it in a document.
const DefaultBackendConcurrency = 16

// DefaultAcquireTimeout bounds how long a request waits for a free slot.
//
// A request that waits indefinitely is worse than one refused: the customer's
// client has its own timeout, so an unbounded queue converts backend slowness
// into a pile of connections pivot is holding for clients that have already
// given up.
const DefaultAcquireTimeout = 5 * time.Second

// ErrNoSlot is returned when no backend slot became free in time. §4 maps it
// to a 503.
var ErrNoSlot = errors.New("server: no backend slot became free")

// Concurrency caps simultaneous backend calls for one replica.
//
// A buffered channel rather than a counter with a condition variable: the
// channel gives the wait a context-cancellable select for free, so a client
// that disconnects stops waiting immediately instead of holding a place in a
// queue for a response nobody will read.
type Concurrency struct {
	slots   chan struct{}
	timeout time.Duration

	// inFlight and waiting are reported by `config view`, because the two
	// together are what tells an operator whether the limit is the bottleneck:
	// slots full with nothing waiting is a well-sized limit, slots full with a
	// queue is one that needs raising or a backend that needs attention.
	inFlight atomic.Int64
	waiting  atomic.Int64

	// refused counts the requests turned away, so a 503 rate is visible
	// without correlating log lines.
	refused atomic.Int64
}

// NewConcurrency returns a limiter with the given number of slots. A limit of
// zero or less means unlimited, which is correct only when something else
// bounds the backend.
func NewConcurrency(limit int, timeout time.Duration) *Concurrency {
	if timeout <= 0 {
		timeout = DefaultAcquireTimeout
	}

	c := &Concurrency{timeout: timeout}

	if limit > 0 {
		c.slots = make(chan struct{}, limit)
	}

	return c
}

// Limit returns the configured number of slots, zero meaning unlimited.
func (c *Concurrency) Limit() int {
	if c.slots == nil {
		return 0
	}

	return cap(c.slots)
}

// Acquire takes a backend slot, waiting up to the configured timeout.
//
// The returned release function must be called exactly once. It is a function
// rather than a Release method so the call site reads `defer release()` and
// cannot release a slot it did not take.
func (c *Concurrency) Acquire(ctx context.Context) (release func(), err error) {
	if c.slots == nil {
		c.inFlight.Add(1)

		return func() { c.inFlight.Add(-1) }, nil
	}

	// The non-blocking path first, so an uncontended request does not pay for
	// a timer.
	select {
	case c.slots <- struct{}{}:
		c.inFlight.Add(1)

		return c.releaser(), nil
	default:
	}

	c.waiting.Add(1)
	defer c.waiting.Add(-1)

	timer := time.NewTimer(c.timeout)
	defer timer.Stop()

	select {
	case c.slots <- struct{}{}:
		c.inFlight.Add(1)

		return c.releaser(), nil
	case <-ctx.Done():
		// The client gave up or the request deadline passed. Reported as the
		// context's error rather than ErrNoSlot, so the pipeline can tell a
		// disconnected client from a saturated backend.
		return nil, ctx.Err()
	case <-timer.C:
		c.refused.Add(1)

		return nil, ErrNoSlot
	}
}

// releaser returns the release function for a held slot.
func (c *Concurrency) releaser() func() {
	var once atomic.Bool

	return func() {
		// Guarded because a double release would free a slot that was never
		// taken, and the limit would drift upwards for the life of the
		// process - a bug that presents as the limit not working months
		// later.
		if !once.CompareAndSwap(false, true) {
			return
		}

		c.inFlight.Add(-1)

		select {
		case <-c.slots:
		default:
		}
	}
}

// Stats reports the limiter's state for `config view` and the admin API.
func (c *Concurrency) Stats() (inFlight, waiting, refused int64, limit int) {
	return c.inFlight.Load(), c.waiting.Load(), c.refused.Load(), c.Limit()
}
