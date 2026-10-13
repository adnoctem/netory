package event

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/adnoctem/netory/pkg/kv"
)

// DefaultLease is how long a claim on an outbox entry is held.
//
// Long enough that a delivery attempt - an SMTP conversation, a webhook POST -
// finishes well inside it, and short enough that an entry whose replica was
// killed mid-delivery is picked up again promptly rather than waiting out a
// timeout nobody is watching.
const DefaultLease = 2 * time.Minute

// Claim is one replica's lease on an outbox entry.
//
// Built on kv.CompareAndSwap, with a lease: a claim without one gives no way to
// recover an entry whose holder died, so the entry would sit claimed forever
// and its notification would never be sent - the failure a persistent outbox
// exists to prevent.
type Claim struct {
	// Holder identifies the replica.
	Holder string `json:"holder"`

	// Until is when the lease expires, after which any replica may take the
	// entry.
	Until time.Time `json:"until"`
}

// Live reports whether the claim is still held at the given time.
func (c *Claim) Live(now time.Time) bool {
	return c != nil && c.Until.After(now)
}

// HeldBy reports whether holder owns this claim right now.
func (c *Claim) HeldBy(holder string, now time.Time) bool {
	return c.Live(now) && c.Holder == holder
}

// ErrNotClaimable is returned when an entry could not be claimed because
// another replica holds it or it changed underneath.
var ErrNotClaimable = errors.New("event: the outbox entry could not be claimed")

// ClaimDue claims up to limit due entries for holder and returns them.
//
// Only for a service running several replicas. protean and signpost have one
// process each and use Pending, which ignores claims entirely - so this adds
// nothing to their delivery path and no behaviour for them to regress.
//
// Each claim is a compare-and-swap against the bytes the entry held when it
// was read, so two replicas cannot both come away believing they hold the same
// entry: the loser is told it lost and moves to the next one. An entry whose
// lease has expired is claimable again, which is how a replica killed
// mid-delivery is recovered.
//
// The consequence to be honest about: at-least-once delivery is unchanged, and
// a lease that expires while its holder is in fact still working - a very slow
// SMTP relay - produces a duplicate notification rather than a lost one. That
// is the right direction, and it is the same trade the outbox already makes by
// marking delivered after the send rather than before.
func (o *Outbox) ClaimDue(
	ctx context.Context, holder string, lease time.Duration, limit int,
) ([]Entry, error) {
	if holder == "" {
		return nil, errors.New("event: a claim needs a holder")
	}

	if lease <= 0 {
		lease = DefaultLease
	}

	now := o.now()
	deadline := now.Add(lease)

	candidates, err := o.claimable(ctx, holder, now)
	if err != nil {
		return nil, err
	}

	// Oldest first, as Pending orders them: the IDs encode creation time, and
	// notifications about one subject should arrive in the order the changes
	// happened.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Event.ID < candidates[j].Event.ID
	})

	claimed := make([]Entry, 0, len(candidates))

	for _, candidate := range candidates {
		if limit > 0 && len(claimed) >= limit {
			break
		}

		entry, took, err := o.claim(ctx, candidate, holder, deadline)
		if err != nil {
			// A failure to claim one entry must not stop the pass: the others
			// are still deliverable, and this one becomes claimable again when
			// its lease lapses.
			o.logger.Debug("could not claim an outbox entry",
				"id", candidate.Event.ID, "error", err)

			continue
		}

		if took {
			claimed = append(claimed, entry)
		}
	}

	return claimed, nil
}

// claimable returns the due entries not currently held by another replica.
func (o *Outbox) claimable(ctx context.Context, holder string, now time.Time) ([]Entry, error) {
	var entries []Entry

	err := o.store.Scan(ctx, pendingPrefix, func(e kv.Entry) error {
		var entry Entry
		if decodeErr := json.Unmarshal(e.Value, &entry); decodeErr != nil {
			// Skipped rather than returned, for the reason Pending records:
			// one corrupt entry must not block every notification behind it.
			//
			//nolint:nilerr // skipping one bad record is the intended behaviour
			o.logger.Error("skipping an undecodable pending outbox entry",
				"key", e.Key, "error", decodeErr)

			return nil
		}

		if entry.NextAttemptAt.After(now) {
			return nil
		}

		// Another replica's live claim is left alone. Our own is taken again,
		// which is what lets a replica that is still working extend its lease
		// rather than lose the entry to itself.
		if entry.Claim.Live(now) && entry.Claim.Holder != holder {
			return nil
		}

		entries = append(entries, entry)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("event: scan claimable: %w", err)
	}

	return entries, nil
}

// claim takes one entry, compare-and-swapping against what it held when read.
func (o *Outbox) claim(
	ctx context.Context, entry Entry, holder string, deadline time.Time,
) (Entry, bool, error) {
	// The expected bytes are the entry re-encoded. encoding/json writes struct
	// fields in declaration order and time.Time round-trips through RFC 3339
	// unchanged, so this reproduces the stored bytes exactly - the same
	// approach signpost's alias swap uses, for the same reason: the store's
	// compare is on bytes and the caller holds a decoded value.
	expected, err := json.Marshal(entry)
	if err != nil {
		return Entry{}, false, fmt.Errorf("event: encode the claimed entry: %w", err)
	}

	updated := entry
	updated.Claim = &Claim{Holder: holder, Until: deadline}

	encoded, err := json.Marshal(updated)
	if err != nil {
		return Entry{}, false, fmt.Errorf("event: encode the claim: %w", err)
	}

	swapped, err := o.store.CompareAndSwap(ctx, pendingPrefix+entry.Event.ID, expected, encoded)
	if err != nil {
		return Entry{}, false, fmt.Errorf("event: claim %s: %w", entry.Event.ID, err)
	}

	if !swapped {
		// Either another replica claimed it first or it changed underneath.
		// Both mean the same thing here: not ours this pass.
		return Entry{}, false, nil
	}

	return updated, true, nil
}

// Release drops a claim without delivering, so another replica can take the
// entry immediately rather than waiting for the lease to lapse.
//
// Called on a graceful shutdown. Without it, every entry a replica held when
// it was asked to stop would sit unclaimable for the rest of its lease - which
// on a rolling deployment is a notification delay for no reason.
func (o *Outbox) Release(ctx context.Context, entry Entry, holder string) error {
	if entry.Claim == nil || entry.Claim.Holder != holder {
		return nil
	}

	expected, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("event: encode the entry to release: %w", err)
	}

	updated := entry
	updated.Claim = nil

	encoded, err := json.Marshal(updated)
	if err != nil {
		return fmt.Errorf("event: encode the released entry: %w", err)
	}

	// A lost swap is not an error: the entry was delivered, re-claimed after
	// our lease lapsed, or otherwise moved on. Either way it is no longer
	// ours to release.
	if _, err := o.store.CompareAndSwap(
		ctx, pendingPrefix+entry.Event.ID, expected, encoded); err != nil {
		return fmt.Errorf("event: release %s: %w", entry.Event.ID, err)
	}

	return nil
}

// Claims returns who holds which pending entries, for `outbox status` on a
// multi-replica deployment.
//
// Worth having: "the queue is not draining" has a very different cause when
// every entry is claimed by a replica that no longer exists than when nothing
// is claimed at all.
func (o *Outbox) Claims(ctx context.Context) (map[string]int, error) {
	now := o.now()
	held := map[string]int{}

	err := o.store.Scan(ctx, pendingPrefix, func(e kv.Entry) error {
		var entry Entry
		if err := json.Unmarshal(e.Value, &entry); err != nil {
			return nil //nolint:nilerr // one bad record must not fail the report
		}

		switch {
		case entry.Claim.Live(now):
			held[entry.Claim.Holder]++
		default:
			held[""]++
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("event: scan claims: %w", err)
	}

	return held, nil
}
