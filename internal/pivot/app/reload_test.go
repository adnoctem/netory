package app_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/internal/pivot/rules"
)

// readOnlyDocument is a minimal rule set for the reload tests.
func readOnlyDocument(t *testing.T, allow string) rules.Document {
	t.Helper()

	doc := rules.Document{}
	doc.Rules.Allow = []rules.Rule{{Methods: []string{"GET"}, Glob: allow}}

	return doc
}

// A fresh pivot denies everything until a rule set is applied. That is the
// right default for a service whose job is to refuse: passing traffic through
// while waiting to be configured is the one behaviour it must never have.
func TestAnUnconfiguredInstanceDeniesEverything(t *testing.T) {
	state := newState(t)

	table := state.Reloader.Table()

	assert.True(t, table.Global.Empty())
	assert.False(t, table.For("any-client").Evaluate("GET", "/api/product").Allowed())
}

func TestApplyGlobalRules(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	version, err := state.Rules.SetGlobal(ctx, readOnlyDocument(t, "/api/product"))
	require.NoError(t, err)
	assert.Positive(t, version)

	// Not yet visible: the table is a snapshot, and a request must never see
	// a half-updated one.
	assert.False(t, state.Reloader.Table().For("c").Evaluate("GET", "/api/product").Allowed())

	require.NoError(t, state.Reloader.Reload(ctx))

	assert.True(t, state.Reloader.Table().For("c").Evaluate("GET", "/api/product").Allowed())
	assert.Equal(t, version, state.Reloader.Table().Version)
}

// A rule set that does not compile is never stored. Storing one would be
// worse than refusing it: every replica would fail its next reload and keep
// serving whatever it had, which is a configuration change that appears to
// have worked and did not.
func TestABrokenRuleSetIsNeverStored(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	good := readOnlyDocument(t, "/api/product")

	_, err := state.Rules.SetGlobal(ctx, good)
	require.NoError(t, err)
	require.NoError(t, state.Reloader.Reload(ctx))

	broken := rules.Document{}
	broken.Rules.Allow = []rules.Rule{{Methods: []string{"PUT"}, Glob: "/api/**"}}

	_, err = state.Rules.SetGlobal(ctx, broken)
	require.ErrorIs(t, err, rules.ErrWriteMethod)

	// The stored set is untouched.
	stored, err := state.Rules.Global(ctx)
	require.NoError(t, err)
	assert.Equal(t, good, stored)
}

// §10.2's accumulation, through the stored records rather than in memory: a
// client's own rules add to the global ones and cannot reopen a global deny.
func TestPerClientRulesAccumulate(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	global := rules.Document{}
	global.Rules.Deny = []rules.Rule{{Methods: []string{"*"}, Glob: "/api/_action/**"}}
	global.Rules.Allow = []rules.Rule{{Methods: []string{"GET"}, Glob: "/api/product"}}

	_, err := state.Rules.SetGlobal(ctx, global)
	require.NoError(t, err)

	clientRules := rules.Document{}
	clientRules.Rules.Allow = []rules.Rule{
		{Methods: []string{"GET"}, Glob: "/api/manufacturer"},
		{Methods: []string{"GET"}, Glob: "/api/_action/**"},
	}

	created, _, err := state.Clients.Create(ctx, app.Client{
		Name:      "Acme",
		Backend:   testBackend(),
		Rules:     &clientRules,
		CreatedBy: "operator",
	})
	require.NoError(t, err)

	require.NoError(t, state.Reloader.Reload(ctx))

	table := state.Reloader.Table()
	set := table.For(created.ID)

	asrt := assert.New(t)
	asrt.True(set.Evaluate("GET", "/api/product").Allowed(), "the global allow still applies")
	asrt.True(set.Evaluate("GET", "/api/manufacturer").Allowed(), "the client's own allow applies")
	asrt.False(set.Evaluate("GET", "/api/_action/order").Allowed(),
		"a client rule must never reopen a globally denied path")

	// A client without rules of its own gets the global set.
	plain := table.For("some-other-client")
	asrt.True(plain.Evaluate("GET", "/api/product").Allowed())
	asrt.False(plain.Evaluate("GET", "/api/manufacturer").Allowed())
}

// One client's broken rules must not stop the whole table being rebuilt: the
// alternative is every other customer serving from a stale set because one
// record is wrong. The client falls back to the global set, which is the
// restrictive direction.
func TestOneBrokenClientDoesNotBreakTheTable(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	_, err := state.Rules.SetGlobal(ctx, readOnlyDocument(t, "/api/product"))
	require.NoError(t, err)

	good, _, err := state.Clients.Create(ctx, app.Client{
		Name: "Good", Backend: testBackend(), CreatedBy: "operator",
	})
	require.NoError(t, err)

	// A client record whose rules cannot compile. Create would refuse this,
	// so it is written through the store directly - which is the real
	// scenario too: a record written by a future version with a rule kind
	// this build does not understand.
	client := state.Store.Client()

	raw, err := client.Do(ctx, client.B().Get().Key("clients:client/"+good.ID).Build()).ToString()
	require.NoError(t, err)

	broken := strings.Replace(raw,
		`"created_by"`,
		`"rules":{"rules":{"allow":[{"methods":["GET"],"glob":"/api/***"}]}},"created_by"`, 1)

	require.NoError(t, client.Do(ctx, client.B().Set().
		Key("clients:client/bad-client").Value(broken).Build()).Error())

	require.NoError(t, state.Reloader.Reload(ctx))

	table := state.Reloader.Table()
	assert.True(t, table.For(good.ID).Evaluate("GET", "/api/product").Allowed(),
		"a healthy client must still be served")
	assert.True(t, table.For("bad-client").Evaluate("GET", "/api/product").Allowed(),
		"the broken client falls back to the global set rather than to nothing")
	assert.False(t, table.For("bad-client").Evaluate("GET", "/api/other").Allowed())
}

// §10.3: a change made through one replica reaches the others. This is the
// whole hot-reload property, with two States standing in for two replicas over
// one Valkey.
func TestAChangeOnOneReplicaReachesAnother(t *testing.T) {
	ctx := context.Background()

	first := newState(t)
	second := newStateSharing(t, first)

	// Neither serves anything yet.
	require.False(t, first.Reloader.Table().For("c").Evaluate("GET", "/api/product").Allowed())
	require.False(t, second.Reloader.Table().For("c").Evaluate("GET", "/api/product").Allowed())

	// The first replica applies a rule set and invalidates.
	_, err := first.Rules.SetGlobal(ctx, readOnlyDocument(t, "/api/product"))
	require.NoError(t, err)
	require.NoError(t, first.Invalidate(ctx))

	// It sees the change at once: an operator who changes a rule and tests it
	// through the same replica must see the new behaviour.
	assert.True(t, first.Reloader.Table().For("c").Evaluate("GET", "/api/product").Allowed())

	// The second replica has not yet rebuilt - its snapshot is still the old
	// one, which is correct.
	assert.False(t, second.Reloader.Table().For("c").Evaluate("GET", "/api/product").Allowed())

	// The version counter is what tells it. Polling is disabled in these
	// tests, so the check is driven directly - which is exactly what the poll
	// loop and the pub/sub announcement both end up calling.
	require.NoError(t, second.Reloader.Reload(ctx))

	assert.True(t, second.Reloader.Table().For("c").Evaluate("GET", "/api/product").Allowed())
	assert.Equal(t, first.Reloader.Table().Version, second.Reloader.Table().Version)
}

// The announcement is what makes convergence fast. The version counter is what
// makes it certain - so this asserts the subscription path end to end, with
// polling off so only the announcement can have delivered it.
func TestAnAnnouncementWakesTheOtherReplica(t *testing.T) {
	ctx := context.Background()

	first := newState(t)
	second := newStateSharing(t, first)

	second.Reloader.Start(ctx)

	_, err := first.Rules.SetGlobal(ctx, readOnlyDocument(t, "/api/product"))
	require.NoError(t, err)

	// Announced on every tick rather than once, because Start returns before
	// the subscription is registered on the server and a pub/sub message
	// published into that window is simply gone - Valkey has no backlog for a
	// channel nobody is listening to yet. In production the poll loop closes
	// that gap; here polling is off on purpose, so the test closes it by
	// re-announcing. The claim is unchanged: polling is disabled, so a second
	// replica that converges at all converged because an announcement reached
	// it.
	require.Eventually(t, func() bool {
		require.NoError(t, first.Invalidate(ctx))

		return second.Reloader.Table().For("c").Evaluate("GET", "/api/product").Allowed()
	}, 10*time.Second, 50*time.Millisecond,
		"the announcement must reach the other replica")
}

// A settings change has to reach the other replicas too, since they cache
// settings for the request path. One version counter covers both, which is
// why ApplySettings bumps it.
func TestSettingsChangesInvalidateToo(t *testing.T) {
	ctx := context.Background()

	first := newState(t)
	second := newStateSharing(t, first)

	settings, err := first.LoadSettings(ctx)
	require.NoError(t, err)

	before := second.Reloader.Table().Version

	settings.BackendURL = "https://backend.example"
	require.NoError(t, first.ApplySettings(ctx, settings))

	assert.Greater(t, first.Reloader.Table().Version, before,
		"a settings change must move the version the other replicas watch")

	// And the other replica picks the settings up when it reloads.
	require.NoError(t, second.Reloader.Reload(ctx))
	require.NoError(t, second.RefreshSettings(ctx))

	updated, err := second.LoadSettings(ctx)
	require.NoError(t, err)
	assert.Equal(t, "https://backend.example", updated.BackendURL)
}

func TestReloadIsIdempotentAndCounted(t *testing.T) {
	ctx := context.Background()
	state := newState(t)

	_, err := state.Rules.SetGlobal(ctx, readOnlyDocument(t, "/api/product"))
	require.NoError(t, err)

	for range 3 {
		require.NoError(t, state.Reloader.Reload(ctx))
	}

	version, reloads, misses, builtAt := state.Reloader.Stats()

	asrt := assert.New(t)
	asrt.Positive(version)
	asrt.GreaterOrEqual(reloads, int64(4), "the first build plus three reloads")
	asrt.Zero(misses)
	asrt.False(builtAt.IsZero())
}

// Stop must be safe whether or not Start ran, and safe twice. A reloader that
// was never started has no loop to wait for, and waiting for one hangs the
// shutdown of anything that built a State without starting its background
// work - which is what every test and every one-off command does.
func TestReloaderStopIsSafeUnstartedAndTwice(t *testing.T) {
	state := newState(t)

	done := make(chan struct{})

	go func() {
		state.Reloader.Stop()
		state.Reloader.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop hung on a reloader that was never started")
	}
}
