package event_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/event"
)

// appendEvents puts n events in the outbox and returns their ids.
func appendEvents(t *testing.T, outbox *event.Outbox, n int) []string {
	t.Helper()

	ctx := context.Background()
	ids := make([]string, 0, n)

	for i := range n {
		e := event.New(event.Type("test.event"), "subject", "a test event").
			WithField("n", string(rune('a'+i)))

		require.NoError(t, outbox.Append(ctx, e))
		ids = append(ids, e.ID)
	}

	return ids
}

func TestClaimDue(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	appendEvents(t, outbox, 3)

	claimed, err := outbox.ClaimDue(ctx, "replica-a", time.Minute, 0)
	require.NoError(t, err)
	require.Len(t, claimed, 3)

	for _, entry := range claimed {
		require.NotNil(t, entry.Claim)
		assert.Equal(t, "replica-a", entry.Claim.Holder)
		assert.True(t, entry.Claim.Live(time.Now()))
	}

	// A second replica finds nothing claimable, which is the whole point:
	// without this, both would deliver all three and every notification would
	// arrive twice per replica.
	other, err := outbox.ClaimDue(ctx, "replica-b", time.Minute, 0)
	require.NoError(t, err)
	assert.Empty(t, other)
}

// Two replicas racing for the same entries: each entry goes to exactly one.
func TestClaimDueIsExclusiveUnderRace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	const events = 20

	appendEvents(t, outbox, events)

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		byID  = map[string]string{}
		total atomic.Int64
	)

	for _, holder := range []string{"a", "b", "c", "d"} {
		wg.Add(1)

		go func(holder string) {
			defer wg.Done()

			claimed, err := outbox.ClaimDue(ctx, holder, time.Minute, 0)
			assert.NoError(t, err)

			total.Add(int64(len(claimed)))

			mu.Lock()
			defer mu.Unlock()

			for _, entry := range claimed {
				if previous, taken := byID[entry.Event.ID]; taken {
					t.Errorf("%s was claimed by both %s and %s",
						entry.Event.ID, previous, holder)
				}

				byID[entry.Event.ID] = holder
			}
		}(holder)
	}

	wg.Wait()

	assert.Equal(t, int64(events), total.Load(), "every entry must be claimed exactly once")
	assert.Len(t, byID, events)
}

// A replica killed mid-delivery leaves a claim nobody will release. Once its
// lease lapses, any replica may take the entry - without which the entry would
// sit claimed forever and its notification would never be sent, the precise
// failure a persistent outbox exists to prevent.
func TestAnExpiredLeaseIsClaimableAgain(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	appendEvents(t, outbox, 1)

	// A very short lease stands in for a replica that died.
	claimed, err := outbox.ClaimDue(ctx, "replica-a", 50*time.Millisecond, 0)
	require.NoError(t, err)
	require.Len(t, claimed, 1)

	// Still held.
	other, err := outbox.ClaimDue(ctx, "replica-b", time.Minute, 0)
	require.NoError(t, err)
	require.Empty(t, other)

	time.Sleep(100 * time.Millisecond)

	recovered, err := outbox.ClaimDue(ctx, "replica-b", time.Minute, 0)
	require.NoError(t, err)
	require.Len(t, recovered, 1, "an expired lease must be reclaimable")
	assert.Equal(t, "replica-b", recovered[0].Claim.Holder)
}

// A replica that still holds an entry re-takes it, extending its own lease
// rather than losing the entry to itself.
func TestAHolderCanRenewItsOwnClaim(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	appendEvents(t, outbox, 1)

	first, err := outbox.ClaimDue(ctx, "replica-a", time.Minute, 0)
	require.NoError(t, err)
	require.Len(t, first, 1)

	again, err := outbox.ClaimDue(ctx, "replica-a", time.Minute, 0)
	require.NoError(t, err)
	require.Len(t, again, 1)

	assert.True(t, again[0].Claim.Until.After(first[0].Claim.Until) ||
		again[0].Claim.Until.Equal(first[0].Claim.Until),
		"the renewed lease must not be earlier than the first")
}

// On a rolling deployment, every entry a stopping replica held would otherwise
// sit unclaimable for the rest of its lease - a notification delay for no
// reason.
func TestRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	appendEvents(t, outbox, 2)

	claimed, err := outbox.ClaimDue(ctx, "replica-a", time.Hour, 0)
	require.NoError(t, err)
	require.Len(t, claimed, 2)

	for _, entry := range claimed {
		require.NoError(t, outbox.Release(ctx, entry, "replica-a"))
	}

	// Available at once rather than in an hour.
	other, err := outbox.ClaimDue(ctx, "replica-b", time.Minute, 0)
	require.NoError(t, err)
	assert.Len(t, other, 2)
}

// Releasing something that is not ours must be a no-op rather than stealing
// it back from whoever holds it now.
func TestReleaseOnlyAffectsOurOwnClaim(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	appendEvents(t, outbox, 1)

	claimed, err := outbox.ClaimDue(ctx, "replica-a", time.Hour, 0)
	require.NoError(t, err)
	require.Len(t, claimed, 1)

	require.NoError(t, outbox.Release(ctx, claimed[0], "replica-b"))

	// Still replica-a's.
	other, err := outbox.ClaimDue(ctx, "replica-b", time.Minute, 0)
	require.NoError(t, err)
	assert.Empty(t, other)
}

func TestClaimDueRespectsTheLimit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	appendEvents(t, outbox, 10)

	claimed, err := outbox.ClaimDue(ctx, "replica-a", time.Minute, 4)
	require.NoError(t, err)
	assert.Len(t, claimed, 4)
}

// "The queue is not draining" has a very different cause when every entry is
// claimed by a replica that no longer exists than when nothing is claimed.
func TestClaims(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	appendEvents(t, outbox, 5)

	held, err := outbox.Claims(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, held[""], "nothing claimed yet")

	_, err = outbox.ClaimDue(ctx, "replica-a", time.Minute, 3)
	require.NoError(t, err)

	held, err = outbox.Claims(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, held["replica-a"])
	assert.Equal(t, 2, held[""])
}

func TestClaimDueRequiresAHolder(t *testing.T) {
	t.Parallel()

	outbox, _ := newOutbox(t)

	_, err := outbox.ClaimDue(context.Background(), "", time.Minute, 0)
	assert.Error(t, err)
}

// Pending ignores claims entirely, so protean and signpost - one process each
// - deliver exactly as they did before claims existed.
func TestPendingIgnoresClaims(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	appendEvents(t, outbox, 3)

	_, err := outbox.ClaimDue(ctx, "replica-a", time.Hour, 0)
	require.NoError(t, err)

	pending, err := outbox.Pending(ctx, 0)
	require.NoError(t, err)
	assert.Len(t, pending, 3, "a single-replica service sees its whole queue regardless of claims")
}

func TestClaimHelpers(t *testing.T) {
	t.Parallel()

	now := time.Now()

	var absent *event.Claim

	asrt := assert.New(t)
	asrt.False(absent.Live(now), "a nil claim is not held")
	asrt.False(absent.HeldBy("a", now))

	live := &event.Claim{Holder: "a", Until: now.Add(time.Minute)}
	asrt.True(live.Live(now))
	asrt.True(live.HeldBy("a", now))
	asrt.False(live.HeldBy("b", now))

	expired := &event.Claim{Holder: "a", Until: now.Add(-time.Minute)}
	asrt.False(expired.Live(now))
	asrt.False(expired.HeldBy("a", now))
}

// With a holder configured the bus claims before delivering, so two replicas
// sharing one outbox each send a given event once rather than both sending it.
func TestBusWithAHolderClaims(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	appendEvents(t, outbox, 6)

	first := newBusWithHolder(t, outbox, "replica-a")
	second := newBusWithHolder(t, outbox, "replica-b")

	firstSink := &countingSink{name: "a"}
	secondSink := &countingSink{name: "b"}

	first.Subscribe(firstSink)
	second.Subscribe(secondSink)

	// One pass each, in sequence: the first replica claims and delivers
	// everything due, so the second finds nothing left.
	delivered, failed := first.DeliverDue(ctx)
	require.Zero(t, failed)
	assert.Equal(t, 6, delivered)

	delivered, failed = second.DeliverDue(ctx)
	assert.Zero(t, failed)
	assert.Zero(t, delivered, "the second replica must not redeliver what the first already sent")

	assert.Equal(t, int64(6), firstSink.count.Load())
	assert.Zero(t, secondSink.count.Load())
}

// A failed attempt drops the claim, so whichever replica is free when the
// backoff elapses retries - holding it across the wait would pin the retry to
// a process that may be gone.
func TestAFailedAttemptReleasesTheClaim(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	outbox, _ := newOutbox(t)

	appendEvents(t, outbox, 1)

	bus := newBusWithHolder(t, outbox, "replica-a")
	bus.Subscribe(&failingSink{})

	_, failed := bus.DeliverDue(ctx)
	require.Equal(t, 1, failed)

	held, err := outbox.Claims(ctx)
	require.NoError(t, err)
	assert.Zero(t, held["replica-a"], "the claim must not survive the attempt")
	assert.Equal(t, 1, held[""])
}

func newBusWithHolder(t *testing.T, outbox *event.Outbox, holder string) *event.Bus {
	t.Helper()

	bus, err := event.NewBus(event.BusOptions{
		Outbox: outbox,
		Logger: silentLogger(t),
		Holder: holder,
		Lease:  time.Minute,

		// Deduplication off: the fixtures differ only by a field, and
		// collapsing them would make the counts meaningless.
		DedupWindow: -1,
	})
	require.NoError(t, err)

	return bus
}

// countingSink records how many events it was given.
type countingSink struct {
	name  string
	count atomic.Int64
}

func (c *countingSink) Name() string { return c.name }

func (c *countingSink) Deliver(context.Context, event.Event) error {
	c.count.Add(1)

	return nil
}

// failingSink always fails, so the retry path runs.
type failingSink struct{}

func (f *failingSink) Name() string { return "failing" }

func (f *failingSink) Deliver(context.Context, event.Event) error {
	return assert.AnError
}
