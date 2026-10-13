package server_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/server"
)

func TestConcurrencyCapsInFlightCalls(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := server.NewConcurrency(3, time.Second)

	releases := make([]func(), 0, 3)

	for range 3 {
		release, err := limiter.Acquire(ctx)
		require.NoError(t, err)

		releases = append(releases, release)
	}

	inFlight, _, _, limit := limiter.Stats()
	assert.Equal(t, int64(3), inFlight)
	assert.Equal(t, 3, limit)

	// The fourth waits and then gives up, which the pipeline answers with a 503.
	start := time.Now()

	_, err := limiter.Acquire(ctx)
	require.ErrorIs(t, err, server.ErrNoSlot)
	assert.GreaterOrEqual(t, time.Since(start), 900*time.Millisecond,
		"the request must have waited for a slot before being refused")

	_, _, refused, _ := limiter.Stats()
	assert.Equal(t, int64(1), refused)

	// Releasing one lets the next in.
	releases[0]()

	release, err := limiter.Acquire(ctx)
	require.NoError(t, err)
	release()

	for _, release := range releases[1:] {
		release()
	}

	inFlight, _, _, _ = limiter.Stats()
	assert.Zero(t, inFlight)
}

// A client that disconnects must stop waiting immediately rather than holding
// a place in the queue for a response nobody will read. The error is the
// context's rather than ErrNoSlot, so the pipeline can tell a gone client from
// a saturated backend.
func TestConcurrencyHonoursContextCancellation(t *testing.T) {
	t.Parallel()

	limiter := server.NewConcurrency(1, time.Minute)

	release, err := limiter.Acquire(context.Background())
	require.NoError(t, err)
	defer release()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)

	go func() {
		_, err := limiter.Acquire(ctx)
		done <- err
	}()

	// Let the goroutine reach the wait, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, server.ErrNoSlot)
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled acquire must return at once, not wait out the timeout")
	}
}

// A double release would free a slot that was never taken, and the limit would
// drift upwards for the life of the process - a bug that presents as the limit
// not working, months later.
func TestConcurrencyReleaseIsIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := server.NewConcurrency(1, 100*time.Millisecond)

	release, err := limiter.Acquire(ctx)
	require.NoError(t, err)

	release()
	release()
	release()

	// Exactly one slot is free, not three.
	first, err := limiter.Acquire(ctx)
	require.NoError(t, err)
	defer first()

	_, err = limiter.Acquire(ctx)
	assert.ErrorIs(t, err, server.ErrNoSlot, "the limit must still be one")
}

func TestConcurrencyUnlimited(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter := server.NewConcurrency(0, time.Second)

	assert.Zero(t, limiter.Limit())

	releases := make([]func(), 0, 100)

	for range 100 {
		release, err := limiter.Acquire(ctx)
		require.NoError(t, err)

		releases = append(releases, release)
	}

	inFlight, _, _, _ := limiter.Stats()
	assert.Equal(t, int64(100), inFlight)

	for _, release := range releases {
		release()
	}
}

// Slots full with a queue is the state an operator needs to see: it means the
// limit needs raising or the backend needs attention.
func TestConcurrencyReportsWaiters(t *testing.T) {
	t.Parallel()

	limiter := server.NewConcurrency(1, time.Second)

	release, err := limiter.Acquire(context.Background())
	require.NoError(t, err)
	defer release()

	var wg sync.WaitGroup

	for range 3 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if release, err := limiter.Acquire(context.Background()); err == nil {
				release()
			}
		}()
	}

	// Sampled while they are queued.
	time.Sleep(100 * time.Millisecond)

	_, waiting, _, _ := limiter.Stats()
	assert.Equal(t, int64(3), waiting)

	wg.Wait()
}

func TestCoalescerSharesOneCall(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	coalescer := server.NewCoalescer()

	var calls atomic.Int64

	// The leader blocks until released, so every follower is guaranteed to
	// arrive while the call is in flight.
	gate := make(chan struct{})

	var (
		wg      sync.WaitGroup
		results = make([]server.Result, 32)
		errs    = make([]error, 32)
	)

	for i := range 32 {
		wg.Add(1)

		go func(n int) {
			defer wg.Done()

			results[n], errs[n] = coalescer.Do(ctx, "same-key", func() (any, error) {
				calls.Add(1)
				<-gate

				return "the-response", nil
			})
		}(i)
	}

	// Let them all pile up on the one in-flight call.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, coalescer.InFlight())

	close(gate)
	wg.Wait()

	assert.Equal(t, int64(1), calls.Load(), "32 identical requests must make one backend call")

	shared := 0

	for i := range results {
		require.NoError(t, errs[i])
		assert.Equal(t, "the-response", results[i].Value)

		if results[i].Shared {
			shared++
		}
	}

	assert.Equal(t, 31, shared, "one leader makes the call and the rest share it")
	assert.Equal(t, int64(31), coalescer.Shared())
	assert.Zero(t, coalescer.InFlight())
}

// Different keys must not share, which is what keeps one customer's response
// away from another: the key is the cache key, which already covers the
// client.
func TestCoalescerKeysAreIndependent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	coalescer := server.NewCoalescer()

	var calls atomic.Int64

	gate := make(chan struct{})

	var wg sync.WaitGroup

	for i := range 4 {
		wg.Add(1)

		go func(n int) {
			defer wg.Done()

			key := string(rune('a' + n))

			result, err := coalescer.Do(ctx, key, func() (any, error) {
				calls.Add(1)
				<-gate

				return key, nil
			})
			assert.NoError(t, err)
			assert.Equal(t, key, result.Value)
			assert.False(t, result.Shared)
		}(i)
	}

	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 4, coalescer.InFlight())

	close(gate)
	wg.Wait()

	assert.Equal(t, int64(4), calls.Load())
}

func TestCoalescerPropagatesTheError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	coalescer := server.NewCoalescer()

	sentinel := errors.New("the backend failed")
	gate := make(chan struct{})

	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, err := coalescer.Do(ctx, "key", func() (any, error) {
				<-gate

				return nil, sentinel
			})
			assert.ErrorIs(t, err, sentinel, "every sharer gets the leader's error")
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(gate)
	wg.Wait()
}

// A request arriving after a call finishes must start a fresh one rather than
// joining a completed call and getting a stale answer.
func TestCoalescerDoesNotReuseAFinishedCall(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	coalescer := server.NewCoalescer()

	var calls atomic.Int64

	for i := range 3 {
		result, err := coalescer.Do(ctx, "key", func() (any, error) {
			return calls.Add(1), nil
		})
		require.NoError(t, err)

		assert.Equal(t, int64(i+1), result.Value, "each sequential request makes its own call")
		assert.False(t, result.Shared)
	}

	assert.Equal(t, int64(3), calls.Load())
}

// A follower that gives up must not cancel the call it was waiting on: another
// follower may still want it, and one client disconnecting is not a reason to
// waste a backend request already in progress.
func TestCoalescerFollowerCancellationDoesNotAbortTheCall(t *testing.T) {
	t.Parallel()

	coalescer := server.NewCoalescer()

	gate := make(chan struct{})
	finished := make(chan struct{})

	go func() {
		_, err := coalescer.Do(context.Background(), "key", func() (any, error) {
			<-gate

			return "done", nil
		})
		assert.NoError(t, err)
		close(finished)
	}()

	time.Sleep(50 * time.Millisecond)

	followerCtx, cancel := context.WithCancel(context.Background())

	followerDone := make(chan error, 1)

	go func() {
		_, err := coalescer.Do(followerCtx, "key", func() (any, error) {
			t.Error("the follower must not run fn")

			return nil, nil
		})
		followerDone <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-followerDone:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled follower must return at once")
	}

	// The leader's call is still running and still completes.
	close(gate)

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("the leader's call must finish even though a follower gave up")
	}
}
