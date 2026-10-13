package event

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/log"
)

// State is where an outbox entry is in its lifecycle.
type State string

const (
	// StatePending means delivery has not yet succeeded.
	StatePending State = "pending"

	// StateDead means delivery failed MaxAttempts times and was abandoned.
	// Dead entries are kept rather than deleted: an alert that never arrived
	// is precisely the thing an operator needs to be able to find afterwards.
	StateDead State = "dead"
)

// Key prefixes within the outbox namespace. Pending and dead entries live
// under different prefixes so that the delivery loop's scan touches only
// pending work - with one prefix it would walk every abandoned entry on every
// pass, and the abandoned ones are the entries that accumulate.
const (
	pendingPrefix = "pending/"
	deadPrefix    = "dead/"
)

// Entry is one event plus its delivery bookkeeping.
type Entry struct {
	Event Event `json:"event"`

	// Attempts is how many delivery attempts have been made.
	Attempts int `json:"attempts"`

	// FirstAttemptAt and LastAttemptAt bracket the delivery history. Both are
	// zero before the first attempt.
	FirstAttemptAt time.Time `json:"first_attempt_at,omitzero"`
	LastAttemptAt  time.Time `json:"last_attempt_at,omitzero"`

	// NextAttemptAt is when this entry becomes eligible again. The delivery
	// loop skips entries scheduled for the future, which is how backoff
	// survives a restart - an in-memory timer would not.
	NextAttemptAt time.Time `json:"next_attempt_at,omitzero"`

	// LastError is why the most recent attempt failed.
	LastError string `json:"last_error,omitempty"`

	// State is pending or dead.
	State State `json:"state"`

	// Claim is the replica currently delivering this entry, if any.
	//
	// Only ever set by a service running several replicas; see claim.go. It is
	// a pointer with omitempty so that a single-replica service's entries
	// encode exactly as they did before claims existed.
	Claim *Claim `json:"claim,omitempty"`
}

// Outbox is a durable queue of events awaiting delivery.
//
// It is persisted through kv.Handle, so protean and signpost get a Badger-backed
// outbox and pivot a Valkey-backed one with no change here. Several pivot
// replicas share one outbox; claims with a lease (claim.go) keep two of them
// from delivering the same attempt.
type Outbox struct {
	store  kv.Handle
	logger *log.Logger
	now    func() time.Time
}

// NewOutbox returns an Outbox persisting into the given namespace handle.
//
// The logger is where an undecodable entry is reported. A nil logger falls back
// to log.Default() rather than being treated as "stay quiet": a corrupt entry
// is an event that will never be delivered, and the scan deliberately steps
// over it to keep the queue draining, so the log is the only place that fact
// can surface.
func NewOutbox(store kv.Handle, logger *log.Logger) *Outbox {
	if logger == nil {
		logger = log.Default()
	}

	return &Outbox{
		store:  store,
		logger: logger.With(slog.String("component", "outbox")),
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// Append persists an event as pending.
//
// This is the step that makes the durability promise real, so it happens before
// any delivery is attempted and its error is returned rather than logged: an
// event that could not be persisted has not been accepted, and the caller needs
// to know that rather than believe a notification is on its way.
func (o *Outbox) Append(ctx context.Context, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}

	entry := Entry{Event: e, State: StatePending}

	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("event: encode entry %s: %w", e.ID, err)
	}

	// SetIfAbsent rather than Set: an ID is unique by construction, so a
	// collision means a caller replayed an event, and silently overwriting
	// would discard the delivery history of the original.
	wrote, err := o.store.SetIfAbsent(ctx, pendingPrefix+e.ID, encoded)
	if err != nil {
		return fmt.Errorf("event: append %s: %w", e.ID, err)
	}

	if !wrote {
		return fmt.Errorf("event: %s is already in the outbox", e.ID)
	}

	return nil
}

// Pending returns the entries eligible for delivery now, oldest first, at most
// limit of them. A limit of zero or less means no limit.
//
// Entries whose NextAttemptAt is in the future are skipped: that is the backoff
// schedule, and reading it from the store rather than a timer is what lets a
// restart resume mid-backoff instead of either retrying everything at once or
// forgetting the schedule.
func (o *Outbox) Pending(ctx context.Context, limit int) ([]Entry, error) {
	now := o.now()

	var entries []Entry
	err := o.store.Scan(ctx, pendingPrefix, func(e kv.Entry) error {
		var entry Entry
		if decodeErr := json.Unmarshal(e.Value, &entry); decodeErr != nil {
			// A single corrupt entry must not stop the whole queue draining:
			// returning here would block every notification behind it,
			// forever. Logged rather than returned, so it is visible without
			// being fatal.
			//
			//nolint:nilerr // skipping one bad record is the intended behaviour
			o.logger.Error("skipping an undecodable pending outbox entry",
				"key", e.Key, "error", decodeErr)

			return nil
		}

		if entry.NextAttemptAt.After(now) {
			return nil
		}

		entries = append(entries, entry)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("event: scan pending: %w", err)
	}

	// kv.Store documents Scan's order as unspecified, so the chronological
	// order the IDs encode has to be applied here rather than assumed. It
	// matters: notifications about one host should arrive in the order the
	// changes happened.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Event.ID < entries[j].Event.ID })

	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	return entries, nil
}

// MarkDelivered removes an entry from the outbox.
//
// Called only after a notifier reports success, which makes delivery
// at-least-once: a crash between the send and this call replays the event. See
// the package documentation for why that is the right direction.
func (o *Outbox) MarkDelivered(ctx context.Context, id string) error {
	if err := o.store.Delete(ctx, pendingPrefix+id); err != nil {
		return fmt.Errorf("event: mark %s delivered: %w", id, err)
	}

	return nil
}

// MarkFailed records a failed attempt and schedules the next one, or moves the
// entry to dead once it has run out of attempts.
func (o *Outbox) MarkFailed(ctx context.Context, entry Entry, cause error, policy RetryPolicy) error {
	now := o.now()

	entry.Attempts++
	entry.LastAttemptAt = now
	if entry.FirstAttemptAt.IsZero() {
		entry.FirstAttemptAt = now
	}

	// The claim goes with the attempt. This replica is finished with the
	// entry whatever happens next, and whichever replica is free when the
	// backoff elapses should be the one that retries - holding the claim
	// across the wait would pin the retry to a process that may be gone.
	entry.Claim = nil
	if cause != nil {
		entry.LastError = cause.Error()
	}

	if entry.Attempts >= policy.MaxAttempts {
		return o.bury(ctx, entry)
	}

	entry.NextAttemptAt = now.Add(policy.Backoff(entry.Attempts))

	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("event: encode entry %s: %w", entry.Event.ID, err)
	}

	if err := o.store.Set(ctx, pendingPrefix+entry.Event.ID, encoded); err != nil {
		return fmt.Errorf("event: reschedule %s: %w", entry.Event.ID, err)
	}

	return nil
}

// bury moves an entry out of the pending prefix and into the dead one.
//
// The dead entry is written before the pending one is deleted. The reverse
// order would turn a crash in between into a silently vanished event, which is
// the one outcome this package exists to prevent; this order can at worst
// duplicate it, which Pending's prefix scan will not even see.
func (o *Outbox) bury(ctx context.Context, entry Entry) error {
	entry.State = StateDead
	entry.NextAttemptAt = time.Time{}

	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("event: encode dead entry %s: %w", entry.Event.ID, err)
	}

	if err := o.store.Set(ctx, deadPrefix+entry.Event.ID, encoded); err != nil {
		return fmt.Errorf("event: record %s as dead: %w", entry.Event.ID, err)
	}

	if err := o.store.Delete(ctx, pendingPrefix+entry.Event.ID); err != nil {
		return fmt.Errorf("event: remove buried %s from pending: %w", entry.Event.ID, err)
	}

	return nil
}

// Dead returns the abandoned entries, oldest first.
//
// Kept and listable on purpose: an alert that never arrived is exactly what an
// operator goes looking for, and silently dropping it would make an outage
// invisible twice over.
func (o *Outbox) Dead(ctx context.Context, limit int) ([]Entry, error) {
	var entries []Entry
	err := o.store.Scan(ctx, deadPrefix, func(e kv.Entry) error {
		var entry Entry
		if decodeErr := json.Unmarshal(e.Value, &entry); decodeErr != nil {
			//nolint:nilerr // as in Pending: one bad record must not hide the rest
			o.logger.Error("skipping an undecodable dead outbox entry",
				"key", e.Key, "error", decodeErr)

			return nil
		}

		entries = append(entries, entry)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("event: scan dead: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Event.ID < entries[j].Event.ID })

	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	return entries, nil
}

// Revive moves a dead entry back to pending with its attempt count reset, for
// an operator who has fixed the relay and wants the backlog sent.
func (o *Outbox) Revive(ctx context.Context, id string) error {
	raw, err := o.store.Get(ctx, deadPrefix+id)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return fmt.Errorf("event: no dead entry %s: %w", id, err)
		}

		return fmt.Errorf("event: read dead entry %s: %w", id, err)
	}

	var entry Entry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return fmt.Errorf("event: decode dead entry %s: %w", id, err)
	}

	entry.State = StatePending
	entry.Attempts = 0
	entry.NextAttemptAt = time.Time{}
	entry.LastError = ""

	encoded, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("event: encode revived entry %s: %w", id, err)
	}

	if err := o.store.Set(ctx, pendingPrefix+id, encoded); err != nil {
		return fmt.Errorf("event: revive %s: %w", id, err)
	}

	if err := o.store.Delete(ctx, deadPrefix+id); err != nil {
		return fmt.Errorf("event: remove revived %s from dead: %w", id, err)
	}

	return nil
}

// Discard permanently removes a dead entry.
func (o *Outbox) Discard(ctx context.Context, id string) error {
	if err := o.store.Delete(ctx, deadPrefix+id); err != nil {
		return fmt.Errorf("event: discard %s: %w", id, err)
	}

	return nil
}

// Counts reports how many entries are pending and dead.
func (o *Outbox) Counts(ctx context.Context) (pending, dead int, err error) {
	pendingKeys, err := o.store.Keys(ctx, pendingPrefix)
	if err != nil {
		return 0, 0, fmt.Errorf("event: count pending: %w", err)
	}

	deadKeys, err := o.store.Keys(ctx, deadPrefix)
	if err != nil {
		return 0, 0, fmt.Errorf("event: count dead: %w", err)
	}

	return len(pendingKeys), len(deadKeys), nil
}
