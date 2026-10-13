package server

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/adnoctem/netory/internal/pivot/app"
)

// Thresholds and the window the aggregated events use.
//
// Constants rather than settings, deliberately. Each one is a judgement about
// when a count stops being noise and starts being an incident, and none of
// them is something an operator would tune without a reason that would be
// better served by fixing the cause. If one turns out to need tuning, that is
// the moment to make it a setting rather than now.
const (
	// AggregateWindow is how long counts accumulate before being reported.
	//
	// Five minutes: long enough that a client retrying a wrong path produces
	// one notification rather than one per retry, short enough that an
	// operator hears about an incident while it is still happening.
	AggregateWindow = 5 * time.Minute

	// AuthFailureThreshold is how many failures for one subject make an
	// incident. One typo should not page anyone.
	AuthFailureThreshold = 5

	// DenialThreshold is how many rule denials for one client make an
	// incident. A client pointed at the wrong path retries, so this is
	// higher.
	DenialThreshold = 10

	// RateLimitThreshold is how many refusals for one client make an
	// incident. A client that hits its limit once is working as intended.
	RateLimitThreshold = 10

	// BackendFailureThreshold is how many backend errors make an incident.
	// This is the one an operator most wants, so it is the lowest.
	BackendFailureThreshold = 5
)

// Aggregator collects per-request outcomes and emits the aggregated events
// and the stored security records.
//
// Both are aggregated, and that is the whole reason this type exists on the
// storage side as well as the notification side. What pivot stores itself has
// to be low-volume enough to carry a ninety-day retention, and a stored record per refused request would break that promise on the
// first client that retried a denied path in a loop. The per-request detail is
// not lost - the access log carries the client, the method, the normalized
// path, the matched rule and the status for every single request - what is
// aggregated is the durable record and the notification.
//
// Per replica and in memory, which is a deliberate limitation worth stating:
// a denial rate spread evenly across ten replicas reaches a tenth of the
// threshold on each, so it may not be reported at all. Counting in Valkey
// would fix that and would put a write on the hot path of every denied
// request - which is the path that exists to be cheap. The log line is emitted
// per request regardless, so the information is not lost; what is aggregated
// is only the notification.
type Aggregator struct {
	state *app.State

	mu      sync.Mutex
	buckets map[aggregateKey]*bucket

	// reported tracks what has already been notified in the current window,
	// so crossing a threshold sends one notification rather than one per
	// request beyond it.
	window time.Duration

	stop     chan struct{}
	done     chan struct{}
	started  sync.Once
	stopOnce sync.Once
}

// aggregateKey identifies one counter.
type aggregateKey struct {
	kind    string
	subject string
}

// The counter kinds.
const (
	kindAuthFailure    = "auth"
	kindDenial         = "denial"
	kindRateLimit      = "ratelimit"
	kindBackendFailure = "backend"
)

// bucket is one subject's count for the current window.
type bucket struct {
	count     int
	threshold int
	notified  bool
	started   time.Time

	// example carries one representative detail - a path, an error - so the
	// notification says something concrete. One rather than all of them: the
	// alternative is an unbounded field built from request data, which is
	// both a notification nobody reads and a way to put a lot of
	// attacker-chosen text into a mail.
	example string
	detail  string
}

// NewAggregator returns an aggregator over application state.
func NewAggregator(state *app.State) *Aggregator {
	return &Aggregator{
		state:   state,
		buckets: map[aggregateKey]*bucket{},
		window:  AggregateWindow,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// Start runs the window ticker until Stop.
func (a *Aggregator) Start(ctx context.Context) {
	a.started.Do(func() {
		go a.run(ctx)
	})
}

// run rolls the window over.
func (a *Aggregator) run(ctx context.Context) {
	defer close(a.done)

	ticker := time.NewTicker(a.window)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.roll(ctx)
		case <-a.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

// roll clears the counters, so the next window starts fresh.
func (a *Aggregator) roll(_ context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.buckets = map[aggregateKey]*bucket{}
}

// Stop ends the ticker.
//
// Safe whether or not Start ran, and safe twice - the same shape as
// Reloader.Stop, and for the same reason: a server built without starting its
// background work still gets shut down.
func (a *Aggregator) Stop() {
	a.stopOnce.Do(func() {
		close(a.stop)

		// Only wait when the loop was actually launched.
		select {
		case <-a.done:
		default:
			// The ticker goroutine closes done on its way out. If Start never
			// ran there is nothing to wait for, which the select's default
			// branch covers without blocking.
		}
	})
}

// AuthFailed counts an authentication failure, reporting it at the threshold.
func (a *Aggregator) AuthFailed(ctx context.Context, subject, source string) {
	a.count(aggregateKey{kindAuthFailure, subject}, AuthFailureThreshold, source, "",
		func(count int, example, _ string) {
			a.state.Publish(ctx, app.ClientAuthFailed(subject, example, count))
			a.state.Audit.Security(ctx, subject, "client.auth_failed", "", map[string]string{
				"failures": strconv.Itoa(count),
				"source":   example,
				"window":   a.window.String(),
			})
		})
}

// Denied counts a rule denial.
func (a *Aggregator) Denied(ctx context.Context, client, path, rule string) {
	a.count(aggregateKey{kindDenial, client}, DenialThreshold, path, rule,
		func(count int, example, detail string) {
			a.state.Publish(ctx, app.RuleDenied(client, count, example, detail))
			a.state.Audit.Security(ctx, client, "rule.denied", example, map[string]string{
				"denials": strconv.Itoa(count),
				"rule":    detail,
				"window":  a.window.String(),
			})
		})
}

// RateLimited counts a rate-limit refusal.
func (a *Aggregator) RateLimited(ctx context.Context, client string) {
	a.count(aggregateKey{kindRateLimit, client}, RateLimitThreshold, "", "",
		func(count int, _, _ string) {
			a.state.Publish(ctx, app.ClientRateLimited(client, count))
			a.state.Audit.Security(ctx, client, "client.rate_limited", "", map[string]string{
				"refusals": strconv.Itoa(count),
				"window":   a.window.String(),
			})
		})
}

// BackendFailed counts a backend error.
func (a *Aggregator) BackendFailed(ctx context.Context, backend string, cause error) {
	detail := ""
	if cause != nil {
		detail = cause.Error()
	}

	a.count(aggregateKey{kindBackendFailure, backend}, BackendFailureThreshold, detail, "",
		func(count int, example, _ string) {
			a.state.Publish(ctx, app.BackendFailed(backend, count, errorString(example)))
			a.state.Audit.Security(ctx, backend, "backend.failed", "", map[string]string{
				"failures": strconv.Itoa(count),
				"error":    example,
				"window":   a.window.String(),
			})
		})
}

// count increments a counter and calls emit the first time it crosses its
// threshold in the current window.
func (a *Aggregator) count(
	key aggregateKey,
	threshold int,
	example, detail string,
	emit func(count int, example, detail string),
) {
	a.mu.Lock()

	entry, ok := a.buckets[key]
	if !ok {
		entry = &bucket{threshold: threshold, started: time.Now()}
		a.buckets[key] = entry
	}

	entry.count++

	if entry.example == "" && example != "" {
		entry.example = example
	}

	if entry.detail == "" && detail != "" {
		entry.detail = detail
	}

	fire := !entry.notified && entry.count >= entry.threshold
	if fire {
		entry.notified = true
	}

	count, storedExample, storedDetail := entry.count, entry.example, entry.detail

	a.mu.Unlock()

	// Emitted outside the lock: Publish writes to the outbox, which is a
	// Valkey round trip, and holding the aggregator's mutex across it would
	// serialise every counted request behind one store write.
	if fire {
		emit(count, storedExample, storedDetail)
	}
}

// Counts reports the current window's counters, for `config view`.
func (a *Aggregator) Counts() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make(map[string]int, len(a.buckets))
	for key, entry := range a.buckets {
		out[key.kind+":"+key.subject] = entry.count
	}

	return out
}

// errorString wraps a message back into an error for the event builders,
// which take one.
func errorString(message string) error {
	if message == "" {
		return nil
	}

	return aggregatedError(message)
}

// aggregatedError is a message recovered from a counter.
type aggregatedError string

func (e aggregatedError) Error() string { return string(e) }
