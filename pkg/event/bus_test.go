package event_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/event"
)

// recordingSink captures what it was asked to deliver and can be told to fail.
type recordingSink struct {
	name string

	mu       sync.Mutex
	received []event.Event
	failWith error
}

func (s *recordingSink) Name() string { return s.name }

func (s *recordingSink) Deliver(_ context.Context, e event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.failWith != nil {
		return s.failWith
	}

	s.received = append(s.received, e)

	return nil
}

func (s *recordingSink) events() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]event.Event(nil), s.received...)
}

func (s *recordingSink) setFailure(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failWith = err
}

func newBus(t *testing.T, opts event.BusOptions) (*event.Bus, *event.Outbox) {
	t.Helper()

	outbox, _ := newOutbox(t)
	opts.Outbox = outbox
	opts.Logger = silentLogger(t)

	bus, err := event.NewBus(opts)
	require.NoError(t, err)

	return bus, outbox
}

func TestNewBusRequiresItsDependencies(t *testing.T) {
	asrt := assert.New(t)

	outbox, _ := newOutbox(t)

	_, err := event.NewBus(event.BusOptions{Logger: silentLogger(t)})
	asrt.Error(err, "an outbox is required")

	// A nil logger is rejected rather than silently dropping background
	// failures, which have no caller to report to.
	_, err = event.NewBus(event.BusOptions{Outbox: outbox})
	asrt.Error(err)
	asrt.Contains(err.Error(), "logger")
}

// Publish persists and returns; it does not wait for delivery. The update
// endpoint must not block on an SMTP relay.
func TestPublishIsDurableBeforeDelivery(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, outbox := newBus(t, event.BusOptions{DedupWindow: -1})
	sink := &recordingSink{name: "smtp"}
	bus.Subscribe(sink)

	e := event.New(typeHostUpdated, "a.example", "changed")
	require.NoError(t, bus.Publish(ctx, e))

	// Durable immediately, delivered only once a pass runs.
	pending, err := outbox.Pending(ctx, 0)
	asrt.NoError(err)
	asrt.Len(pending, 1, "the event must be persisted before any delivery is attempted")
	asrt.Empty(sink.events())

	delivered, failed := bus.DeliverDue(ctx)
	asrt.Equal(1, delivered)
	asrt.Zero(failed)

	require.Len(t, sink.events(), 1)
	asrt.Equal(e.ID, sink.events()[0].ID)

	pending, err = outbox.Pending(ctx, 0)
	asrt.NoError(err)
	asrt.Empty(pending, "a delivered event leaves the outbox")
}

func TestDeliverToEverySink(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, _ := newBus(t, event.BusOptions{DedupWindow: -1})
	smtp := &recordingSink{name: "smtp"}
	webhook := &recordingSink{name: "webhook"}
	bus.Subscribe(smtp)
	bus.Subscribe(webhook)

	require.NoError(t, bus.Publish(ctx, event.New(typeHostUpdated, "a.example", "changed")))

	delivered, _ := bus.DeliverDue(ctx)
	asrt.Equal(1, delivered)
	asrt.Len(smtp.events(), 1)
	asrt.Len(webhook.events(), 1)
	asrt.Len(bus.Sinks(), 2)
}

// With no sink configured, events must accumulate rather than be discarded, so
// configuring a notifier later still sends the backlog.
func TestEventsAreRetainedWithNoSinks(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, outbox := newBus(t, event.BusOptions{DedupWindow: -1})

	require.NoError(t, bus.Publish(ctx, event.New(typeHostUpdated, "a.example", "changed")))

	delivered, failed := bus.DeliverDue(ctx)
	asrt.Zero(delivered)
	asrt.Zero(failed)

	pending, err := outbox.Pending(ctx, 0)
	asrt.NoError(err)
	asrt.Len(pending, 1, "an event must not be dropped just because no notifier exists yet")

	// Subscribing later drains it.
	sink := &recordingSink{name: "smtp"}
	bus.Subscribe(sink)

	delivered, _ = bus.DeliverDue(ctx)
	asrt.Equal(1, delivered)
	asrt.Len(sink.events(), 1)
}

// A failed delivery is retried, and the event stays in the outbox meanwhile.
func TestFailedDeliveryIsRetained(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, outbox := newBus(t, event.BusOptions{
		DedupWindow: -1,
		Policy:      event.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond, Jitter: 0},
	})

	sink := &recordingSink{name: "smtp"}
	sink.setFailure(errors.New("relay refused"))
	bus.Subscribe(sink)

	require.NoError(t, bus.Publish(ctx, event.New(typeHostUpdated, "a.example", "changed")))

	delivered, failed := bus.DeliverDue(ctx)
	asrt.Zero(delivered)
	asrt.Equal(1, failed)

	time.Sleep(5 * time.Millisecond)

	pending, err := outbox.Pending(ctx, 0)
	asrt.NoError(err)
	require.Len(t, pending, 1)
	asrt.Equal(1, pending[0].Attempts)
	asrt.Contains(pending[0].LastError, "relay refused")

	// Once the relay recovers, the retry succeeds.
	sink.setFailure(nil)
	delivered, failed = bus.DeliverDue(ctx)
	asrt.Equal(1, delivered)
	asrt.Zero(failed)
	asrt.Len(sink.events(), 1)
}

// An entry is retained if any sink failed, and resent to all of them. That is
// the documented at-least-once consequence of not tracking per-sink progress.
func TestOneFailingSinkRetainsTheEventForAll(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, _ := newBus(t, event.BusOptions{
		DedupWindow: -1,
		Policy:      event.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond, Jitter: 0},
	})

	working := &recordingSink{name: "webhook"}
	broken := &recordingSink{name: "smtp"}
	broken.setFailure(errors.New("relay refused"))
	bus.Subscribe(working)
	bus.Subscribe(broken)

	require.NoError(t, bus.Publish(ctx, event.New(typeHostUpdated, "a.example", "changed")))

	_, failed := bus.DeliverDue(ctx)
	asrt.Equal(1, failed)
	asrt.Len(working.events(), 1)

	time.Sleep(5 * time.Millisecond)
	broken.setFailure(nil)

	delivered, _ := bus.DeliverDue(ctx)
	asrt.Equal(1, delivered)
	asrt.Len(broken.events(), 1)
	asrt.Len(working.events(), 2,
		"the working sink sees the event twice: delivery is at-least-once, by design")
}

// Deduplication is what stops a flapping connection sending one mail per
// address change.
func TestDeduplicationCollapsesAFlappingHost(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, _ := newBus(t, event.BusOptions{DedupWindow: time.Hour})
	sink := &recordingSink{name: "smtp"}
	bus.Subscribe(sink)

	// Ten updates for the same host, with different addresses - the fields
	// differ, which is exactly what must not make them count as distinct.
	for i := range 10 {
		e := event.New(typeHostUpdated, "flapping.example", "address changed").
			WithField("ip", "203.0.113."+string(rune('0'+i)))
		require.NoError(t, bus.Publish(ctx, e))
	}

	// A different subject and a different type are not duplicates.
	require.NoError(t, bus.Publish(ctx, event.New(typeHostUpdated, "other.example", "changed")))
	require.NoError(t, bus.Publish(ctx, event.New(typeAuthFailed, "flapping.example", "bad token")))

	delivered, _ := bus.DeliverDue(ctx)
	asrt.Equal(3, delivered, "ten flaps collapse to one, plus the two genuinely distinct events")
	asrt.Len(sink.events(), 3)
}

func TestDeduplicationCanBeDisabled(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, _ := newBus(t, event.BusOptions{DedupWindow: -1})
	sink := &recordingSink{name: "smtp"}
	bus.Subscribe(sink)

	for range 5 {
		require.NoError(t, bus.Publish(ctx, event.New(typeHostUpdated, "a.example", "changed")))
	}

	delivered, _ := bus.DeliverDue(ctx)
	asrt.Equal(5, delivered, "a negative window means every event is delivered")
}

// The loop's first act is a delivery pass, which is the restart half of
// "nothing lost on restart".
func TestStartDeliversWhatAPreviousProcessLeftPending(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, outbox := newBus(t, event.BusOptions{DedupWindow: -1})

	// Appended straight to the outbox, as if a previous process had published
	// it and died before delivering.
	e := event.New(typeHostUpdated, "a.example", "changed")
	require.NoError(t, outbox.Append(ctx, e))

	sink := &recordingSink{name: "smtp"}
	bus.Subscribe(sink)

	bus.Start(ctx, time.Hour) // long interval: only the initial pass can deliver
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = bus.Stop(stopCtx)
	})

	asrt.Eventually(func() bool { return len(sink.events()) == 1 }, 5*time.Second, 10*time.Millisecond,
		"the delivery loop must pick up work left by a previous process")
}

// Publish wakes the loop, so an idle system delivers promptly rather than
// waiting out the poll interval.
func TestPublishWakesTheDeliveryLoop(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, _ := newBus(t, event.BusOptions{DedupWindow: -1})
	sink := &recordingSink{name: "smtp"}
	bus.Subscribe(sink)

	bus.Start(ctx, time.Hour)
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = bus.Stop(stopCtx)
	})

	require.NoError(t, bus.Publish(ctx, event.New(typeHostUpdated, "a.example", "changed")))

	asrt.Eventually(func() bool { return len(sink.events()) == 1 }, 5*time.Second, 10*time.Millisecond,
		"a published event must not wait for the poll interval")
}

func TestStopIsIdempotent(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, _ := newBus(t, event.BusOptions{DedupWindow: -1})
	bus.Start(ctx, time.Hour)

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	asrt.NoError(bus.Stop(stopCtx))
	asrt.NoError(bus.Stop(stopCtx), "Stop must be safe to call twice")
}

// Publishing from many goroutines is the real usage: the update endpoint
// handles concurrent requests and each can emit an event.
func TestConcurrentPublish(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	bus, outbox := newBus(t, event.BusOptions{DedupWindow: -1})

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			for j := range 16 {
				e := event.New(typeHostUpdated, "host", "changed").
					WithField("writer", string(rune('a'+i))).
					WithField("n", string(rune('a'+j)))
				if err := bus.Publish(ctx, e); err != nil {
					t.Errorf("Publish: %v", err)

					return
				}
			}
		}(i)
	}
	wg.Wait()

	p, _, err := outbox.Counts(ctx)
	asrt.NoError(err)
	asrt.Equal(8*16, p, "no event may be lost or rejected as a duplicate ID under concurrency")
}

func TestRetryPolicyBackoffGrowsAndIsCapped(t *testing.T) {
	asrt := assert.New(t)

	policy := event.RetryPolicy{MaxAttempts: 64, BaseDelay: time.Second, MaxDelay: time.Minute, Jitter: 0}

	asrt.Equal(time.Second, policy.Backoff(1))
	asrt.Equal(2*time.Second, policy.Backoff(2))
	asrt.Equal(4*time.Second, policy.Backoff(3))
	asrt.Equal(time.Minute, policy.Backoff(10), "the delay is capped")

	// The cap must hold at absurd attempt counts: 1s shifted left 60 times
	// overflows int64 and would come out negative, scheduling the retry in the
	// past and spinning.
	for _, attempts := range []int{0, -1, 30, 60, 1_000, 1 << 20} {
		delay := policy.Backoff(attempts)
		asrt.GreaterOrEqual(delay, time.Duration(0), "attempts=%d produced a negative delay", attempts)
		asrt.LessOrEqual(delay, time.Minute, "attempts=%d exceeded MaxDelay", attempts)
	}
}

// Jitter must stay within the cap, or a configured MaxDelay would not mean
// what it says.
func TestRetryPolicyJitterStaysWithinTheCap(t *testing.T) {
	asrt := assert.New(t)

	policy := event.RetryPolicy{MaxAttempts: 10, BaseDelay: time.Second, MaxDelay: 10 * time.Second, Jitter: 0.5}

	var sawVariation bool
	first := policy.Backoff(5)
	for range 200 {
		delay := policy.Backoff(5)
		asrt.LessOrEqual(delay, 10*time.Second)
		asrt.GreaterOrEqual(delay, 5*time.Second, "jitter must not reduce the delay below half")

		if delay != first {
			sawVariation = true
		}
	}

	asrt.True(sawVariation, "jitter must actually vary the delay, or synchronised retries stay synchronised")
}

func TestRetryPolicyNormalise(t *testing.T) {
	asrt := assert.New(t)

	got := event.RetryPolicy{}.Normalise()
	asrt.Equal(event.DefaultRetryPolicy, got, "the zero policy takes every default")

	partial := event.RetryPolicy{MaxAttempts: 3}.Normalise()
	asrt.Equal(3, partial.MaxAttempts, "a specified field is kept")
	asrt.Equal(event.DefaultRetryPolicy.BaseDelay, partial.BaseDelay)

	asrt.Equal(event.DefaultRetryPolicy.Jitter, event.RetryPolicy{Jitter: 2}.Normalise().Jitter,
		"an out-of-range jitter falls back to the default")

	// Zero means unset, not "no jitter" - consistent with every other field.
	// A caller wanting deterministic backoff bypasses Normalise, as the
	// backoff tests above do.
	asrt.Equal(event.DefaultRetryPolicy.Jitter, event.RetryPolicy{Jitter: 0}.Normalise().Jitter)
	asrt.Zero(event.RetryPolicy{BaseDelay: time.Second, MaxDelay: time.Second, Jitter: 0}.Backoff(1)-time.Second,
		"a policy used without Normalise keeps its literal zero jitter")
}
