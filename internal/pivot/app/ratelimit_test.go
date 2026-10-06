package app_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/app"
	"github.com/adnoctem/netory/pkg/kv/valkeykv"
)

// AddressEnv names the Valkey these tests run against, matching the one
// pkg/kv/valkeykv uses so one running server serves both suites.
const AddressEnv = "VALKEY_TEST_ADDR"

const defaultAddress = "127.0.0.1:6379"

// namespaceCounter keeps each test's namespace distinct, since one Valkey
// serves the whole suite and the tests run in parallel.
var namespaceCounter atomic.Uint64

// runID makes the namespaces distinct between runs as well as between tests.
//
// A counter alone is not enough and the reason is worth recording: buckets
// live for MinBucketTTL after their last use, so a second `go test` within
// that minute would reuse the first run's namespaces and find tokens already
// spent. That failed as "request 4 of the burst was refused" - a test
// isolation problem wearing the costume of a limiter bug.
var runID = func() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		// A fixed value still beats a counter alone: the tests clean up after
		// themselves, so this only matters for a run killed mid-way.
		return "fixed"
	}

	return hex.EncodeToString(buf)
}()

func valkeyAddress(t *testing.T) string {
	t.Helper()

	addr := strings.TrimSpace(os.Getenv(AddressEnv))
	if addr == "" {
		addr = defaultAddress
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Skipf("no Valkey reachable at %s (%v)\n"+
			"Start one with:  docker run --rm -p 6379:6379 valkey/valkey:8-alpine\n"+
			"Or point %s at an existing server.", addr, err, AddressEnv)
	}

	_ = conn.Close()

	return addr
}

// newLimiter returns a limiter in a namespace of its own, with a clock the
// test controls.
//
// A controlled clock rather than sleeping: a token bucket is a function of
// elapsed time, so the whole of its behaviour can be exercised by moving the
// clock, and a suite that slept for its refills would take minutes to assert
// what this asserts in milliseconds.
func newLimiter(t *testing.T) (*app.Limiter, *clock) {
	t.Helper()

	addr := valkeyAddress(t)

	store, err := valkeykv.New(valkeykv.Options{Address: []string{addr}, DB: testDB})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	namespace := fmt.Sprintf("rl-%s-%d", runID, namespaceCounter.Add(1))
	clk := &clock{now: time.Now()}

	limiter, err := app.NewLimiter(store, namespace, clk.Now)
	require.NoError(t, err)

	// Buckets outlive the test by MinBucketTTL, so they are removed rather
	// than left to expire - a killed run would otherwise leave a namespace a
	// later run could collide with.
	t.Cleanup(func() {
		for _, client := range []string{
			"client-1", "client-2", "client-unlimited", "probe",
		} {
			_ = limiter.Reset(context.Background(), client)
		}
	})

	return limiter, clk
}

// clock is a movable clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

func TestBurstThenRefill(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter, clk := newLimiter(t)

	// Ten at once, then one more every two seconds.
	limit := app.RateLimit{Capacity: 10, PerSecond: 0.5}

	// The whole burst goes through without the clock moving, which is the
	// property a token bucket has and a sliding window does not.
	for i := range 10 {
		decision, err := limiter.Allow(ctx, "client-1", limit)
		require.NoError(t, err)
		require.True(t, decision.Allowed, "request %d of the burst", i+1)
	}

	refused, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)

	asrt := assert.New(t)
	asrt.False(refused.Allowed, "the eleventh request exceeds the burst")
	asrt.Zero(refused.Remaining)
	asrt.Positive(refused.RetryAfter, "a refusal must say when to come back")

	// Not yet refilled.
	clk.advance(time.Second)

	refused, err = limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)
	asrt.False(refused.Allowed, "half a token is not a token")

	// One more second, and the bucket holds a whole token.
	clk.advance(time.Second)

	allowed, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)
	asrt.True(allowed.Allowed)
}

// Retry-After travels in whole seconds, so a sub-second delay would round to
// zero and invite an immediate retry that fails again.
func TestRetryAfterHasASecondFloor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter, _ := newLimiter(t)

	// Refills fast, so the true delay is milliseconds.
	limit := app.RateLimit{Capacity: 1, PerSecond: 100}

	_, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)

	refused, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)

	require.False(t, refused.Allowed)
	assert.GreaterOrEqual(t, refused.RetryAfter, time.Second)
}

// The bucket never fills past its capacity, or a client idle overnight would
// wake with an unbounded allowance.
func TestBucketDoesNotOverfill(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter, clk := newLimiter(t)

	limit := app.RateLimit{Capacity: 5, PerSecond: 1}

	_, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)

	// Idle for an hour.
	clk.advance(time.Hour)

	for i := range 5 {
		decision, err := limiter.Allow(ctx, "client-1", limit)
		require.NoError(t, err)
		require.True(t, decision.Allowed, "request %d after a long idle", i+1)
	}

	refused, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)
	assert.False(t, refused.Allowed, "an idle client gets a full bucket, not an unbounded one")
}

// Replicas' clocks differ by milliseconds, and a limiter that punished a
// client for being served by the replica with the slower clock would be
// unexplainable from the outside.
func TestClockGoingBackwardsDoesNotCharge(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter, clk := newLimiter(t)

	limit := app.RateLimit{Capacity: 3, PerSecond: 1}

	_, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)

	clk.advance(-time.Minute)

	// Two tokens are still there; going back in time must not have removed
	// them, and must not have added any either.
	for range 2 {
		decision, err := limiter.Allow(ctx, "client-1", limit)
		require.NoError(t, err)
		assert.True(t, decision.Allowed)
	}

	refused, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)
	assert.False(t, refused.Allowed)
}

func TestLimitsArePerClient(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter, _ := newLimiter(t)

	limit := app.RateLimit{Capacity: 2, PerSecond: 1}

	for range 2 {
		decision, err := limiter.Allow(ctx, "client-1", limit)
		require.NoError(t, err)
		require.True(t, decision.Allowed)
	}

	refused, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)
	require.False(t, refused.Allowed)

	// A second client is unaffected: the limits exist to keep customers fair
	// to each other, so one exhausting its allowance must not touch another's.
	other, err := limiter.Allow(ctx, "client-2", limit)
	require.NoError(t, err)
	assert.True(t, other.Allowed)
}

// The refill, the check and the write happen in one Lua execution, so two
// replicas checking the same client concurrently cannot both see the same
// token and both take it. A read-then-write would allow exactly that, and the
// limit would be approximately rather than actually enforced.
func TestConcurrentCallersCannotOvershoot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter, _ := newLimiter(t)

	const capacity = 20

	limit := app.RateLimit{Capacity: capacity, PerSecond: 0.001}

	var (
		wg      sync.WaitGroup
		allowed atomic.Int64
	)

	for range 100 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			decision, err := limiter.Allow(ctx, "client-1", limit)
			assert.NoError(t, err)

			if decision.Allowed {
				allowed.Add(1)
			}
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(capacity), allowed.Load(),
		"exactly the capacity may pass, however many callers race for it")
}

// A zero capacity means no limit rather than no requests: a client record
// written before limits were configured must not silently stop working.
func TestZeroLimitIsUnlimited(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter, _ := newLimiter(t)

	for _, limit := range []app.RateLimit{
		{},
		{Capacity: 0, PerSecond: 10},
		{Capacity: 10, PerSecond: 0},
	} {
		require.True(t, limit.Unlimited(), "%+v", limit)

		for range 50 {
			decision, err := limiter.Allow(ctx, "client-unlimited", limit)
			require.NoError(t, err)
			require.True(t, decision.Allowed)
		}
	}
}

func TestAllowN(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter, _ := newLimiter(t)

	limit := app.RateLimit{Capacity: 10, PerSecond: 1}

	decision, err := limiter.AllowN(ctx, "client-1", limit, 7)
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
	assert.Equal(t, 3, decision.Remaining)

	refused, err := limiter.AllowN(ctx, "client-1", limit, 5)
	require.NoError(t, err)
	assert.False(t, refused.Allowed, "a cost larger than the remainder is refused")

	// And the refusal took nothing, so a smaller request still fits.
	allowed, err := limiter.AllowN(ctx, "client-1", limit, 3)
	require.NoError(t, err)
	assert.True(t, allowed.Allowed)
}

// An operator who has just raised a limit needs the old bucket gone, or it
// keeps refusing until it refills at the old rate.
func TestReset(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	limiter, _ := newLimiter(t)

	limit := app.RateLimit{Capacity: 1, PerSecond: 0.001}

	_, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)

	refused, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)
	require.False(t, refused.Allowed)

	require.NoError(t, limiter.Reset(ctx, "client-1"))

	allowed, err := limiter.Allow(ctx, "client-1", limit)
	require.NoError(t, err)
	assert.True(t, allowed.Allowed, "a reset bucket starts from full")
}

func TestRateLimitValidation(t *testing.T) {
	t.Parallel()

	asrt := assert.New(t)
	asrt.NoError(app.RateLimit{}.Validate())
	asrt.NoError(app.RateLimit{Capacity: 10, PerSecond: 0.5}.Validate())
	asrt.Error(app.RateLimit{Capacity: -1}.Validate())
	asrt.Error(app.RateLimit{PerSecond: -1}.Validate())
	asrt.Error(app.RateLimit{Capacity: 10}.Validate(),
		"a capacity with no rate is a bucket that never refills")
}

func TestRateLimitRendering(t *testing.T) {
	t.Parallel()

	asrt := assert.New(t)
	asrt.Equal("unlimited", app.RateLimit{}.String())
	asrt.Equal("10 burst, 0.5/s", app.RateLimit{Capacity: 10, PerSecond: 0.5}.String())
	asrt.Equal(20*time.Second, app.RateLimit{Capacity: 10, PerSecond: 0.5}.Window())
	asrt.Zero(app.RateLimit{}.Window())
}

func TestNewLimiterValidatesItsNamespace(t *testing.T) {
	t.Parallel()

	addr := valkeyAddress(t)

	store, err := valkeykv.New(valkeykv.Options{Address: []string{addr}, DB: testDB})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	// A malformed namespace must fail here rather than on the first limited
	// request.
	_, err = app.NewLimiter(store, "has:colon", nil)
	assert.Error(t, err)

	_, err = app.NewLimiter(nil, "ratelimit", nil)
	assert.Error(t, err)
}

// valkeyAddress is shared with app_test.go: one Valkey serves both.
