package event

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adnoctem/netory/pkg/log"
)

// Sink delivers an event. pkg/notify's Notifier satisfies it, which is how the
// bus stays unaware of SMTP and webhooks.
type Sink interface {
	// Name identifies the sink in logs and events.
	Name() string

	// Deliver sends the event. A nil error means delivered; any error is
	// retried according to the bus's RetryPolicy.
	Deliver(ctx context.Context, e Event) error
}

// Bus persists events and drives their delivery to the registered sinks.
//
// Publish returns as soon as the event is durable, not when it is delivered.
// That ordering is the whole design: the DynDNS2 update endpoint must not wait
// on an SMTP relay to answer a client, and an event that is on disk will be
// delivered eventually even if the process dies in between.
type Bus struct {
	outbox *Outbox
	logger *log.Logger
	policy RetryPolicy
	dedup  *deduplicator

	// holder and lease configure claiming; holder is empty in a
	// single-replica service.
	holder string
	lease  time.Duration

	// running reports whether the delivery loop was ever launched, so Stop
	// knows whether there is anything to wait for.
	running atomic.Bool

	// sinks is replaced wholesale under the lock rather than mutated, so the
	// delivery loop can take a snapshot and iterate it without holding the
	// lock across a network call.
	mu    sync.RWMutex
	sinks []Sink

	// wake lets Publish nudge a sleeping delivery loop, so the common case -
	// an idle system where one event arrives - delivers in milliseconds rather
	// than waiting out the poll interval.
	wake chan struct{}

	started sync.Once
	stop    chan struct{}
	done    chan struct{}
}

// BusOptions configures a Bus.
type BusOptions struct {
	// Outbox persists events. Required.
	Outbox *Outbox

	// Logger is required: a delivery failure that is retried in the background
	// has no caller to return an error to, so the log is the only place it can
	// be reported.
	Logger *log.Logger

	// Policy governs retries. Zero fields take the defaults.
	Policy RetryPolicy

	// PollInterval is how often the delivery loop looks for due work when it
	// has not been woken. Zero uses DefaultPollInterval.
	PollInterval time.Duration

	// DedupWindow collapses identical events occurring within it. Zero uses
	// DefaultDedupWindow; negative disables deduplication.
	DedupWindow time.Duration

	// BatchSize bounds how many entries one delivery pass handles. Zero uses
	// DefaultBatchSize.
	BatchSize int

	// Holder makes the delivery loop claim entries before delivering them,
	// identifying this process. Set it only in a service running several
	// replicas; see claim.go.
	//
	// Empty - which is protean's and signpost's case - means the loop reads
	// the queue with Pending and claims nothing, exactly as it did before
	// claims existed. One process cannot duplicate a notification with
	// itself, so the bookkeeping would buy nothing and cost a
	// compare-and-swap per entry.
	Holder string

	// Lease is how long a claim is held. Zero uses DefaultLease.
	Lease time.Duration
}

// Defaults for the delivery loop.
const (
	// DefaultPollInterval is the fallback poll cadence. It only governs
	// retries and events published while the loop was busy, since Publish
	// wakes the loop directly.
	DefaultPollInterval = 30 * time.Second

	// DefaultDedupWindow collapses identical events within a minute of each
	// other. protean section 8.2 requires that a flapping connection does not
	// send one mail per address change, and this is that control.
	DefaultDedupWindow = time.Minute

	// DefaultBatchSize bounds a delivery pass, so a large backlog is drained
	// in chunks that each get a chance to observe shutdown.
	DefaultBatchSize = 64
)

// NewBus returns a Bus. Start must be called to begin delivering.
func NewBus(opts BusOptions) (*Bus, error) {
	if opts.Outbox == nil {
		return nil, errors.New("event: an outbox is required")
	}

	if opts.Logger == nil {
		return nil, errors.New("event: a logger is required, background delivery failures have nowhere else to go")
	}

	window := opts.DedupWindow
	if window == 0 {
		window = DefaultDedupWindow
	}

	lease := opts.Lease
	if lease <= 0 {
		lease = DefaultLease
	}

	return &Bus{
		outbox: opts.Outbox,
		logger: opts.Logger.With(slog.String("component", "event")),
		policy: opts.Policy.Normalise(),
		dedup:  newDeduplicator(window),
		holder: opts.Holder,
		lease:  lease,
		wake:   make(chan struct{}, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}, nil
}

// Subscribe registers a sink. Safe to call before or after Start.
func (b *Bus) Subscribe(s Sink) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.sinks = append(append([]Sink(nil), b.sinks...), s)
}

// Sinks returns the registered sinks.
func (b *Bus) Sinks() []Sink {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return append([]Sink(nil), b.sinks...)
}

// Publish persists an event and returns. Delivery happens in the background.
//
// A duplicate within the deduplication window is dropped and reported as
// delivered, so a flapping connection produces one notification rather than
// one per flap.
func (b *Bus) Publish(ctx context.Context, e Event) error {
	if b.dedup.seen(e, time.Now()) {
		b.logger.Debug("event suppressed as duplicate", "type", e.Type, "subject", e.Subject)

		return nil
	}

	if err := b.outbox.Append(ctx, e); err != nil {
		return err
	}

	b.logger.Debug("event published", "id", e.ID, "type", e.Type, "subject", e.Subject)
	b.nudge()

	return nil
}

// nudge wakes the delivery loop without blocking. The channel is buffered to
// one, so a burst of publishes coalesces into a single wake-up - which is what
// is wanted, since one pass drains whatever is due.
func (b *Bus) nudge() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// Start begins the delivery loop. It returns immediately; call Stop to shut it
// down. Starting twice is a no-op.
func (b *Bus) Start(ctx context.Context, pollInterval time.Duration) {
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}

	b.started.Do(func() {
		b.running.Store(true)

		go b.run(ctx, pollInterval)
	})
}

// Stop ends the delivery loop and waits for the current pass to finish.
//
// A bus whose loop was never started returns at once. Without that check it
// would wait out the caller's whole context for a goroutine that does not
// exist - which is not hypothetical: a service that assembles its state
// without starting background delivery, as every test and every one-off
// command does, closes that state on the way out and would pay the full
// shutdown timeout for nothing.
func (b *Bus) Stop(ctx context.Context) error {
	select {
	case <-b.stop:
		// already stopping
	default:
		close(b.stop)
	}

	if !b.running.Load() {
		return nil
	}

	select {
	case <-b.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("event: delivery loop did not stop in time: %w", ctx.Err())
	}
}

// run is the delivery loop.
func (b *Bus) run(ctx context.Context, pollInterval time.Duration) {
	defer close(b.done)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// An immediate first pass picks up whatever a previous process left
	// pending, which is the restart half of "nothing lost on restart".
	b.deliverDue(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stop:
			return
		case <-ticker.C:
			b.deliverDue(ctx)
		case <-b.wake:
			b.deliverDue(ctx)
		}
	}
}

// DeliverDue runs one delivery pass synchronously and reports how many entries
// were delivered and how many failed. Exposed for tests and for a `notifier
// test` style command that should not wait for the loop.
func (b *Bus) DeliverDue(ctx context.Context) (delivered, failed int) {
	return b.deliverDue(ctx)
}

func (b *Bus) deliverDue(ctx context.Context) (delivered, failed int) {
	sinks := b.Sinks()
	if len(sinks) == 0 {
		// No sinks yet. Entries stay pending rather than being discarded, so
		// configuring a notifier later still sends the backlog.
		return 0, 0
	}

	entries, err := b.due(ctx)
	if err != nil {
		b.logger.Error("could not read the outbox", "error", err)

		return 0, 0
	}

	for i, entry := range entries {
		select {
		case <-ctx.Done():
			b.releaseRemaining(entries[i:])

			return delivered, failed
		case <-b.stop:
			b.releaseRemaining(entries[i:])

			return delivered, failed
		default:
		}

		if b.deliverOne(ctx, entry, sinks) {
			delivered++
		} else {
			failed++
		}
	}

	return delivered, failed
}

// due returns the entries this pass should deliver.
//
// With a holder configured the entries are claimed first, so that one of
// several replicas delivers each one. Without a holder the queue is read as it
// always was.
func (b *Bus) due(ctx context.Context) ([]Entry, error) {
	if b.holder == "" {
		return b.outbox.Pending(ctx, DefaultBatchSize)
	}

	return b.outbox.ClaimDue(ctx, b.holder, b.lease, DefaultBatchSize)
}

// releaseRemaining drops the claims on entries a cut-short pass did not reach.
//
// Without it, a replica asked to stop mid-batch would leave the rest of its
// claimed entries unclaimable for the remainder of their lease - on a rolling
// deployment, a notification delay for no reason. The context used is
// deliberately detached: the pass stopped because its own context was
// cancelled, and inheriting it would make every release fail.
//
//nolint:contextcheck // detaching from the cancelled context is the point
func (b *Bus) releaseRemaining(entries []Entry) {
	if b.holder == "" || len(entries) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, entry := range entries {
		if err := b.outbox.Release(ctx, entry, b.holder); err != nil {
			b.logger.Debug("could not release an outbox claim",
				"id", entry.Event.ID, "error", err)
		}
	}
}

// deliverOne sends an entry to every sink, reporting whether it is done with.
//
// An entry is retained if *any* sink failed, and resent to all of them on the
// retry. That is the at-least-once consequence of not tracking per-sink
// progress: a working webhook gets a duplicate because the SMTP relay was
// down. Per-sink state would avoid it and is not worth the bookkeeping until
// something actually needs it - a duplicate alert is a nuisance, a missing one
// is a fault.
func (b *Bus) deliverOne(ctx context.Context, entry Entry, sinks []Sink) bool {
	var failures []error

	for _, sink := range sinks {
		if err := sink.Deliver(ctx, entry.Event); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", sink.Name(), err))
		}
	}

	if len(failures) == 0 {
		if err := b.outbox.MarkDelivered(ctx, entry.Event.ID); err != nil {
			b.logger.Error("delivered but could not clear the outbox entry",
				"id", entry.Event.ID, "error", err)

			return false
		}

		b.logger.Debug("event delivered", "id", entry.Event.ID, "type", entry.Event.Type)

		return true
	}

	cause := errors.Join(failures...)
	if err := b.outbox.MarkFailed(ctx, entry, cause, b.policy); err != nil {
		b.logger.Error("could not record a delivery failure", "id", entry.Event.ID, "error", err)

		return false
	}

	attempts := entry.Attempts + 1
	if attempts >= b.policy.MaxAttempts {
		// Logged at error, not warn: this event will never be delivered, and
		// it is the last chance anyone has to notice.
		b.logger.Error("giving up on an event after repeated delivery failures",
			"id", entry.Event.ID, "type", entry.Event.Type, "attempts", attempts, "error", cause)
	} else {
		b.logger.Warn("event delivery failed, will retry",
			"id", entry.Event.ID, "type", entry.Event.Type, "attempts", attempts, "error", cause)
	}

	return false
}
