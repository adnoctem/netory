package event_test

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
	"github.com/adnoctem/netory/pkg/log"
)

const (
	typeHostUpdated = event.Type("host.updated")
	typeAuthFailed  = event.Type("auth.failed")
)

// newOutbox returns an Outbox over a real in-memory Badger store, not a mock.
// The outbox's whole job is durability, so testing it against a fake store
// would test the fake.
func newOutbox(t *testing.T) (*event.Outbox, kv.Store) {
	t.Helper()

	store, err := badgerkv.New(badgerkv.Options{InMemory: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	handle, err := kv.In(store, "outbox")
	require.NoError(t, err)

	return event.NewOutbox(handle, silentLogger(t)), store
}

func silentLogger(t *testing.T) *log.Logger {
	t.Helper()

	return log.New(log.WithOutput(&strings.Builder{}), log.WithLevel(slog.LevelError))
}

func TestNewPopulatesIDAndTime(t *testing.T) {
	asrt := assert.New(t)

	e := event.New(typeHostUpdated, "example.org", "address changed")
	asrt.Len(e.ID, event.IDLen)
	asrt.Equal(typeHostUpdated, e.Type)
	asrt.Equal("example.org", e.Subject)
	asrt.False(e.OccurredAt.IsZero())
	asrt.Equal(time.UTC, e.OccurredAt.Location(), "times are stored in UTC")
	asrt.NoError(e.Validate())
}

// IDs must sort chronologically: the outbox is scanned by key prefix and relies
// on that to replay events in the order they happened.
func TestIDsSortChronologically(t *testing.T) {
	asrt := assert.New(t)

	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	var ids []string
	for i := range 200 {
		ids = append(ids, event.NewID(base.Add(time.Duration(i)*time.Millisecond)))
	}

	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	asrt.Equal(ids, sorted, "lexicographic order must match chronological order")

	// And the timestamp round-trips, so an operator can tell when a dead
	// outbox entry was created from its ID alone.
	got, ok := event.TimeFromID(ids[0])
	asrt.True(ok)
	asrt.WithinDuration(base, got, time.Millisecond)

	_, ok = event.TimeFromID("not-an-id")
	asrt.False(ok)
}

func TestIDsAreUniqueWithinOneInstant(t *testing.T) {
	asrt := assert.New(t)

	// Same timestamp every time: uniqueness has to come from the random half,
	// or two events in one nanosecond would collide and the second Append
	// would be rejected as a replay.
	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	seen := make(map[string]struct{}, 10_000)
	for range 10_000 {
		id := event.NewID(at)
		_, dup := seen[id]
		if !asrt.False(dup, "duplicate ID %s", id) {
			return
		}
		seen[id] = struct{}{}
	}
}

// WithField must copy, since one Event is handed to several sinks and a mutation
// under one of them would change what the others see.
func TestWithFieldDoesNotMutate(t *testing.T) {
	asrt := assert.New(t)

	original := event.New(typeHostUpdated, "example.org", "").WithField("ip", "203.0.113.1")
	derived := original.WithField("ip", "203.0.113.9").WithField("family", "ipv4")

	asrt.Equal("203.0.113.1", original.Field("ip"), "the original must be unchanged")
	asrt.Empty(original.Field("family"))
	asrt.Equal("203.0.113.9", derived.Field("ip"))
	asrt.Equal("ipv4", derived.Field("family"))
}

func TestValidateRejectsIncompleteEvents(t *testing.T) {
	asrt := assert.New(t)

	asrt.Error(event.Event{Type: typeHostUpdated, OccurredAt: time.Now()}.Validate(), "no ID")
	asrt.Error(event.Event{ID: "x", OccurredAt: time.Now()}.Validate(), "no type")
	asrt.Error(event.Event{ID: "x", Type: typeHostUpdated}.Validate(), "no timestamp")
}

func TestOutboxAppendAndPending(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	outbox, _ := newOutbox(t)

	first := event.New(typeHostUpdated, "a.example", "changed")
	second := event.New(typeHostUpdated, "b.example", "changed")
	require.NoError(t, outbox.Append(ctx, first))
	require.NoError(t, outbox.Append(ctx, second))

	pending, err := outbox.Pending(ctx, 0)
	asrt.NoError(err)
	require.Len(t, pending, 2)
	asrt.Equal(first.ID, pending[0].Event.ID, "pending entries come back oldest first")
	asrt.Equal(second.ID, pending[1].Event.ID)
	asrt.Equal(event.StatePending, pending[0].State)
	asrt.Zero(pending[0].Attempts)

	p, d, err := outbox.Counts(ctx)
	asrt.NoError(err)
	asrt.Equal(2, p)
	asrt.Zero(d)

	// The limit is honoured, so a large backlog is drained in bounded passes.
	limited, err := outbox.Pending(ctx, 1)
	asrt.NoError(err)
	asrt.Len(limited, 1)
	asrt.Equal(first.ID, limited[0].Event.ID)
}

// An ID is unique by construction, so a repeat means a replay - and silently
// overwriting would discard the original's delivery history.
func TestOutboxRejectsDuplicateAppend(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	outbox, _ := newOutbox(t)

	e := event.New(typeHostUpdated, "a.example", "changed")
	require.NoError(t, outbox.Append(ctx, e))

	err := outbox.Append(ctx, e)
	asrt.Error(err)
	asrt.Contains(err.Error(), "already in the outbox")
}

func TestOutboxRejectsInvalidEvent(t *testing.T) {
	ctx := context.Background()
	outbox, _ := newOutbox(t)

	assert.Error(t, outbox.Append(ctx, event.Event{Type: typeHostUpdated}))
}

func TestOutboxMarkDelivered(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	outbox, _ := newOutbox(t)

	e := event.New(typeHostUpdated, "a.example", "changed")
	require.NoError(t, outbox.Append(ctx, e))
	require.NoError(t, outbox.MarkDelivered(ctx, e.ID))

	pending, err := outbox.Pending(ctx, 0)
	asrt.NoError(err)
	asrt.Empty(pending)

	// Idempotent, because a crash can replay the mark.
	asrt.NoError(outbox.MarkDelivered(ctx, e.ID))
}

// Backoff must survive a restart, which is why NextAttemptAt is persisted
// rather than held in a timer.
func TestOutboxBackoffHidesAnEntryUntilItIsDue(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	outbox, _ := newOutbox(t)

	e := event.New(typeHostUpdated, "a.example", "changed")
	require.NoError(t, outbox.Append(ctx, e))

	entries, err := outbox.Pending(ctx, 0)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	policy := event.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Hour, MaxDelay: time.Hour, Jitter: 0}
	require.NoError(t, outbox.MarkFailed(ctx, entries[0], errors.New("relay down"), policy))

	// Scheduled an hour out, so it is not due now.
	due, err := outbox.Pending(ctx, 0)
	asrt.NoError(err)
	asrt.Empty(due, "an entry in backoff must not be returned as due")

	p, d, err := outbox.Counts(ctx)
	asrt.NoError(err)
	asrt.Equal(1, p, "it is still pending, just not yet due")
	asrt.Zero(d)
}

func TestOutboxRecordsFailureDetail(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	outbox, _ := newOutbox(t)

	e := event.New(typeHostUpdated, "a.example", "changed")
	require.NoError(t, outbox.Append(ctx, e))

	entries, err := outbox.Pending(ctx, 0)
	require.NoError(t, err)

	// Zero delay so the entry comes straight back as due.
	policy := event.RetryPolicy{MaxAttempts: 5, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond, Jitter: 0}
	require.NoError(t, outbox.MarkFailed(ctx, entries[0], errors.New("relay down"), policy))

	time.Sleep(5 * time.Millisecond)

	entries, err = outbox.Pending(ctx, 0)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	asrt.Equal(1, entries[0].Attempts)
	asrt.Contains(entries[0].LastError, "relay down")
	asrt.False(entries[0].FirstAttemptAt.IsZero())
	asrt.False(entries[0].LastAttemptAt.IsZero())
}

// Running out of attempts moves the entry to dead rather than deleting it: an
// alert that never arrived is exactly what an operator goes looking for.
func TestOutboxBuriesAnEntryAfterMaxAttempts(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	outbox, _ := newOutbox(t)

	e := event.New(typeHostUpdated, "a.example", "changed")
	require.NoError(t, outbox.Append(ctx, e))

	policy := event.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond, Jitter: 0}
	for attempt := 1; attempt <= 3; attempt++ {
		entries, err := outbox.Pending(ctx, 0)
		require.NoError(t, err)
		require.Len(t, entries, 1, "attempt %d", attempt)

		require.NoError(t, outbox.MarkFailed(ctx, entries[0], errors.New("relay down"), policy))
		time.Sleep(2 * time.Millisecond)
	}

	pending, err := outbox.Pending(ctx, 0)
	asrt.NoError(err)
	asrt.Empty(pending)

	dead, err := outbox.Dead(ctx, 0)
	asrt.NoError(err)
	require.Len(t, dead, 1)
	asrt.Equal(e.ID, dead[0].Event.ID)
	asrt.Equal(event.StateDead, dead[0].State)
	asrt.Equal(3, dead[0].Attempts)
	asrt.Contains(dead[0].LastError, "relay down")

	p, d, err := outbox.Counts(ctx)
	asrt.NoError(err)
	asrt.Zero(p)
	asrt.Equal(1, d)
}

func TestOutboxReviveAndDiscard(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	outbox, _ := newOutbox(t)

	e := event.New(typeHostUpdated, "a.example", "changed")
	require.NoError(t, outbox.Append(ctx, e))

	policy := event.RetryPolicy{MaxAttempts: 1, BaseDelay: time.Nanosecond, MaxDelay: time.Nanosecond, Jitter: 0}
	entries, err := outbox.Pending(ctx, 0)
	require.NoError(t, err)
	require.NoError(t, outbox.MarkFailed(ctx, entries[0], errors.New("relay down"), policy))

	dead, err := outbox.Dead(ctx, 0)
	require.NoError(t, err)
	require.Len(t, dead, 1)

	// An operator who fixed the relay wants the backlog sent.
	require.NoError(t, outbox.Revive(ctx, e.ID))

	revived, err := outbox.Pending(ctx, 0)
	asrt.NoError(err)
	require.Len(t, revived, 1)
	asrt.Equal(event.StatePending, revived[0].State)
	asrt.Zero(revived[0].Attempts, "reviving resets the attempt count")
	asrt.Empty(revived[0].LastError)

	dead, err = outbox.Dead(ctx, 0)
	asrt.NoError(err)
	asrt.Empty(dead, "a revived entry is no longer dead")

	asrt.Error(outbox.Revive(ctx, "no-such-id"))

	// And discarding works on a dead entry.
	require.NoError(t, outbox.MarkFailed(ctx, revived[0], errors.New("still down"), policy))
	require.NoError(t, outbox.Discard(ctx, e.ID))

	dead, err = outbox.Dead(ctx, 0)
	asrt.NoError(err)
	asrt.Empty(dead)
}

// The durability promise: pending work survives the process that created it.
func TestOutboxSurvivesReopen(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	dir := t.TempDir()

	store, err := badgerkv.New(badgerkv.Options{Path: dir})
	require.NoError(t, err)

	handle, err := kv.In(store, "outbox")
	require.NoError(t, err)

	e := event.New(typeHostUpdated, "a.example", "changed")
	require.NoError(t, event.NewOutbox(handle, silentLogger(t)).Append(ctx, e))
	require.NoError(t, store.Close())

	reopened, err := badgerkv.New(badgerkv.Options{Path: dir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	handle, err = kv.In(reopened, "outbox")
	require.NoError(t, err)

	pending, err := event.NewOutbox(handle, silentLogger(t)).Pending(ctx, 0)
	asrt.NoError(err)
	require.Len(t, pending, 1, "a pending event must survive a restart")
	asrt.Equal(e.ID, pending[0].Event.ID)
	asrt.Equal("a.example", pending[0].Event.Subject)
}

// One corrupt entry must not block every notification behind it.
func TestOutboxSkipsACorruptEntry(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	outbox, store := newOutbox(t)

	good := event.New(typeHostUpdated, "a.example", "changed")
	require.NoError(t, outbox.Append(ctx, good))

	// Write something that is not an entry, directly under the pending prefix.
	require.NoError(t, store.Set(ctx, "outbox", "pending/"+event.NewID(time.Now()), []byte("{not json")))

	pending, err := outbox.Pending(ctx, 0)
	asrt.NoError(err, "a corrupt entry must not fail the whole scan")
	require.Len(t, pending, 1)
	asrt.Equal(good.ID, pending[0].Event.ID)
}
