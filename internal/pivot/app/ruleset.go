package app

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/adnoctem/netory/internal/pivot/rules"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/valkeykv"
	"github.com/adnoctem/netory/pkg/log"
)

// Keys in the config namespace that hold the rule set.
const (
	globalRulesKey  = "rules/global"
	rulesVersionKey = "rules/version"
)

// ReloadChannel is the Valkey pub/sub channel rule changes are announced on.
const ReloadChannel = "pivot:rules"

// DefaultReloadPoll is how often a replica checks the rule version when no
// announcement has woken it.
//
// The poll is not a fallback nobody needs. Valkey pub/sub is fire-and-forget:
// a replica that was reconnecting when a change was announced never hears it,
// and would then serve the old rule set indefinitely. The version counter in
// Valkey is the source of truth and this poll is what guarantees convergence;
// the announcement only makes it fast.
const DefaultReloadPoll = 15 * time.Second

// RuleTable is the compiled rule set a replica serves from.
//
// Immutable and swapped whole behind an atomic.Pointer, the same arrangement
// signpost uses for its route table and for the same reason: a request must
// never see a rule set that is half-updated, because the half it saw might be
// the half without the deny.
type RuleTable struct {
	// Version is the rule version this table was built from.
	Version int64

	// Global is the instance-wide rule set.
	Global *rules.Set

	// byClient holds each client's merged set - global plus that client's own
	// additions - so the request path does no merging.
	byClient map[string]*rules.Set

	// BuiltAt is when the table was compiled, for `config view`.
	BuiltAt time.Time
}

// For returns the rule set that applies to a client.
//
// A client with no rules of its own gets the global set. A client that is not
// in the table at all gets the global set too, which is the safe direction: an
// unknown client has already failed authentication by the time rules are
// consulted, and falling back to the global set cannot be more permissive than
// the merged one would be.
func (t *RuleTable) For(client string) *rules.Set {
	if t == nil {
		return rules.EmptySet()
	}

	if set, ok := t.byClient[client]; ok {
		return set
	}

	if t.Global != nil {
		return t.Global
	}

	return rules.EmptySet()
}

// Clients returns how many clients have rules of their own.
func (t *RuleTable) Clients() int { return len(t.byClient) }

// RuleStore holds the global rule document and the version counter.
type RuleStore struct {
	store kv.Handle
}

// NewRuleStore returns the rule repository over the config namespace.
func NewRuleStore(store kv.Handle) *RuleStore { return &RuleStore{store: store} }

// Global returns the stored global rule document.
//
// A missing document is the empty one, which permits nothing. That is the
// right default for a service whose job is to refuse: a pivot started against
// a fresh Valkey denies every request until an operator applies a rule set,
// rather than passing traffic through while it waits to be configured.
func (r *RuleStore) Global(ctx context.Context) (rules.Document, error) {
	raw, err := r.store.Get(ctx, globalRulesKey)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return rules.EmptyDocument(), nil
		}

		return rules.Document{}, fmt.Errorf("app: read the global rules: %w", err)
	}

	doc, err := rules.Parse(raw)
	if err != nil {
		return rules.Document{}, fmt.Errorf("app: decode the global rules: %w", err)
	}

	return doc, nil
}

// SetGlobal stores the global rule document and bumps the version.
//
// The document is compiled first, so a rule set that does not compile is never
// stored. Storing one would be worse than refusing it: every replica would
// then fail its next reload and keep serving whatever it had, which is a
// configuration change that appears to have worked and did not.
func (r *RuleStore) SetGlobal(ctx context.Context, doc rules.Document) (int64, error) {
	if _, err := rules.Compile(doc, rules.ScopeGlobal); err != nil {
		return 0, err
	}

	encoded, err := rules.EncodeJSON(doc)
	if err != nil {
		return 0, err
	}

	if err := r.store.Set(ctx, globalRulesKey, encoded); err != nil {
		return 0, fmt.Errorf("app: store the global rules: %w", err)
	}

	return r.Bump(ctx)
}

// Version returns the current rule version.
func (r *RuleStore) Version(ctx context.Context) (int64, error) {
	raw, err := r.store.Get(ctx, rulesVersionKey)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return 0, nil
		}

		return 0, fmt.Errorf("app: read the rule version: %w", err)
	}

	version, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("app: the rule version %q is not a number: %w", raw, err)
	}

	return version, nil
}

// Bump increments the rule version and returns the new value.
//
// Called after any change that affects what a replica should serve: the global
// rules, and also a client being added, updated or removed, since a client
// carries its own rules and its own limit. One counter for all of it rather
// than one per thing: a replica only needs to know that *something* changed,
// and a single number is the cheapest possible way to tell it.
func (r *RuleStore) Bump(ctx context.Context) (int64, error) {
	version, err := r.store.Increment(ctx, rulesVersionKey, 1)
	if err != nil {
		return 0, fmt.Errorf("app: bump the rule version: %w", err)
	}

	return version, nil
}

// Reloader keeps a replica's RuleTable in step with Valkey.
//
// This is §10.3's hot reload. The version counter in Valkey is authoritative
// and the pub/sub announcement is an optimisation on top of it, which is the
// only arrangement that converges: pub/sub has no delivery guarantee, so a
// replica that misses an announcement has to find out some other way, and a
// poll of one integer every fifteen seconds is that way.
type Reloader struct {
	table   atomic.Pointer[RuleTable]
	rules   *RuleStore
	clients *Clients
	client  valkey.Client
	logger  *log.Logger
	poll    time.Duration

	// wake is signalled by an announcement, so a change is picked up in
	// milliseconds rather than at the next poll.
	wake chan struct{}

	stop chan struct{}
	done chan struct{}

	// started records whether Start launched the loops, and stopOnce keeps
	// Stop idempotent. Both exist because Stop waits for the loop to finish:
	// without started it would wait forever on a loop that was never
	// launched, which is the state every test and every one-off command
	// leaves the reloader in.
	started  atomic.Bool
	stopOnce sync.Once

	// reloads and misses count successful rebuilds and failed attempts, for
	// `config view`: a replica whose misses are climbing is one serving a
	// stale rule set, which is exactly what an operator needs to see.
	reloads atomic.Int64
	misses  atomic.Int64
}

// ReloaderOptions are the dependencies a Reloader needs.
type ReloaderOptions struct {
	Rules   *RuleStore
	Clients *Clients
	Store   *valkeykv.Store
	Logger  *log.Logger

	// Poll overrides DefaultReloadPoll. A negative value disables polling,
	// which leaves only the announcements - for a test, not for production.
	Poll time.Duration
}

// NewReloader builds a Reloader and compiles the current rule set once.
//
// The first build happens here rather than in the background, so `server
// start` fails on an uncompilable stored rule set instead of coming up and
// denying everything.
func NewReloader(ctx context.Context, opts ReloaderOptions) (*Reloader, error) {
	if opts.Rules == nil || opts.Clients == nil {
		return nil, errors.New("app: the reloader needs the rule and client stores")
	}

	if opts.Logger == nil {
		return nil, errors.New("app: the reloader needs a logger")
	}

	reloader := &Reloader{
		rules:   opts.Rules,
		clients: opts.Clients,
		logger:  opts.Logger,
		poll:    opts.Poll,
		wake:    make(chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	if opts.Store != nil {
		reloader.client = opts.Store.Client()
	}

	if reloader.poll == 0 {
		reloader.poll = DefaultReloadPoll
	}

	if err := reloader.Reload(ctx); err != nil {
		return nil, err
	}

	return reloader, nil
}

// Table returns the current rule table. Never nil.
func (r *Reloader) Table() *RuleTable {
	if table := r.table.Load(); table != nil {
		return table
	}

	return &RuleTable{Global: rules.EmptySet()}
}

// Reload rebuilds the rule table from Valkey and swaps it in.
func (r *Reloader) Reload(ctx context.Context) error {
	version, err := r.rules.Version(ctx)
	if err != nil {
		r.misses.Add(1)

		return err
	}

	doc, err := r.rules.Global(ctx)
	if err != nil {
		r.misses.Add(1)

		return err
	}

	global, err := rules.Compile(doc, rules.ScopeGlobal)
	if err != nil {
		r.misses.Add(1)

		return fmt.Errorf("app: the stored global rules do not compile: %w", err)
	}

	configured, err := r.clients.List(ctx)
	if err != nil {
		r.misses.Add(1)

		return err
	}

	byClient := make(map[string]*rules.Set, len(configured))

	for _, client := range configured {
		if client.Rules == nil {
			continue
		}

		set, err := rules.Compile(*client.Rules, rules.ScopeClient)
		if err != nil {
			// One client's broken rules must not stop the whole table being
			// rebuilt: the alternative is that every other customer keeps
			// serving from a stale set because one record is wrong. The
			// client falls back to the global set, which is the restrictive
			// direction, and the log says so.
			r.logger.Error("a client's own rules do not compile, falling back to the global set",
				"client", client.ID, "error", err)

			continue
		}

		byClient[client.ID] = rules.Merge(global, set)
	}

	r.table.Store(&RuleTable{
		Version:  version,
		Global:   global,
		byClient: byClient,
		BuiltAt:  time.Now().UTC(),
	})

	r.reloads.Add(1)

	deny, allow, routes := global.Counts()
	r.logger.Debug("rule table built",
		"version", version,
		"deny", deny,
		"allow", allow,
		"routes", routes,
		"clients_with_rules", len(byClient))

	return nil
}

// Announce publishes a rule change so every replica reloads at once.
//
// Best-effort by design: a failure to announce is logged and not returned,
// because the change is already stored and the version counter already
// incremented. Every replica will pick it up at its next poll, so an
// announcement that did not go out costs latency rather than correctness.
func (r *Reloader) Announce(ctx context.Context, version int64) {
	if r.client == nil {
		return
	}

	err := r.client.Do(ctx, r.client.B().Publish().
		Channel(ReloadChannel).
		Message(strconv.FormatInt(version, 10)).
		Build()).Error()
	if err != nil {
		r.logger.Warn("could not announce a rule change; replicas will pick it up by polling",
			"version", version, "error", err)
	}
}

// Start runs the reload loop until Stop.
//
// Calling it twice is a no-op rather than a second loop, so a caller unsure
// whether the state was started cannot end up with two.
//
// It returns before the subscription is established: the subscribe goroutine
// has to reach Valkey first, and an announcement published into that window is
// lost, because a channel with no subscriber has no backlog. That is why the
// version counter and the poll loop exist - the announcement is an
// optimisation for the common case, never the mechanism convergence depends
// on.
func (r *Reloader) Start(ctx context.Context) {
	if !r.started.CompareAndSwap(false, true) {
		return
	}

	go r.pollLoop(ctx)

	if r.client != nil {
		go r.subscribe(ctx)
	}
}

// pollLoop reloads when the stored version differs from the built one.
func (r *Reloader) pollLoop(ctx context.Context) {
	defer close(r.done)

	if r.poll < 0 {
		// Polling disabled: the loop still exists so Stop has something to
		// wait for, and announcements still drive reloads.
		for {
			select {
			case <-r.wake:
				r.reloadIfChanged(ctx)
			case <-r.stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}

	ticker := time.NewTicker(r.poll)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.reloadIfChanged(ctx)
		case <-r.wake:
			r.reloadIfChanged(ctx)
		case <-r.stop:
			return
		case <-ctx.Done():
			return
		}
	}
}

// reloadIfChanged rebuilds only when the stored version has moved.
//
// Comparing first rather than rebuilding unconditionally: a rebuild reads
// every client record, and doing that every fifteen seconds on an instance
// with hundreds of customers would be a steady load on Valkey for nothing.
// Reading one integer is the cheap question.
func (r *Reloader) reloadIfChanged(ctx context.Context) {
	version, err := r.rules.Version(ctx)
	if err != nil {
		r.misses.Add(1)
		r.logger.Warn("could not read the rule version", "error", err)

		return
	}

	if version == r.Table().Version {
		return
	}

	if err := r.Reload(ctx); err != nil {
		r.logger.Error("could not reload the rule table; continuing with the previous one",
			"error", err)

		return
	}

	r.logger.Info("rule table reloaded", "version", version)
}

// subscribe listens for announcements and wakes the poll loop.
//
// A dedicated connection, because a subscribed connection cannot serve other
// commands. Receive blocks until the context ends or the connection drops, and
// a drop is retried - a replica that stopped listening would fall back to
// polling, which converges but slowly, so reconnecting is worth the loop.
func (r *Reloader) subscribe(ctx context.Context) {
	for {
		select {
		case <-r.stop:
			return
		case <-ctx.Done():
			return
		default:
		}

		err := r.client.Receive(ctx,
			r.client.B().Subscribe().Channel(ReloadChannel).Build(),
			func(msg valkey.PubSubMessage) {
				r.logger.Debug("rule change announced", "version", msg.Message)
				r.Wake()
			})
		if err != nil {
			select {
			case <-r.stop:
				return
			case <-ctx.Done():
				return
			default:
			}

			r.logger.Warn("the rule-change subscription dropped; reconnecting",
				"error", err, "fallback_poll", r.poll.String())

			select {
			case <-time.After(time.Second):
			case <-r.stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}
}

// Wake asks the loop to check the version now.
func (r *Reloader) Wake() {
	select {
	case r.wake <- struct{}{}:
	default:
		// A check is already queued. The loop reads the version itself, so a
		// coalesced wake loses nothing.
	}
}

// Stop ends the reload loop.
//
// Safe whether or not Start ran, and safe to call twice. A reloader that was
// never started has no loop to wait for, and waiting for one hangs the
// shutdown of anything that built a State without starting its background
// work - which is what every test and every one-off command does.
func (r *Reloader) Stop() {
	r.stopOnce.Do(func() {
		close(r.stop)

		if r.started.Load() {
			<-r.done
		}
	})
}

// Stats reports the reloader's state for `config view`.
func (r *Reloader) Stats() (version int64, reloads, misses int64, builtAt time.Time) {
	table := r.Table()

	return table.Version, r.reloads.Load(), r.misses.Load(), table.BuiltAt
}
