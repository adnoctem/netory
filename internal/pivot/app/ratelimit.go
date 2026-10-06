package app

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/adnoctem/netory/pkg/kv/valkeykv"
)

// RateLimit is one client's limit.
//
// A token bucket rather than a sliding window, which is §10.5's decision and
// Max's preference. The reasoning is that pivot proxies: a short burst costs
// the backend a handful of requests it can absorb, and pivot's own concurrency
// limit (§7.1) is what actually protects production from volume. A sliding
// window would reject a client's third request in a second even when the
// backend is idle, which for an API whose clients page through results in
// bursts is a limiter that fights normal use.
//
// The bucket's capacity is therefore the burst a client may take at once, and
// the rate is what it may sustain.
type RateLimit struct {
	// Capacity is the burst size, in requests.
	Capacity int `json:"capacity"`

	// PerSecond is the sustained refill rate, in requests per second. A
	// fractional value is meaningful: 0.5 is one request every two seconds.
	PerSecond float64 `json:"per_second"`
}

// Unlimited reports whether the limit permits everything.
//
// A zero capacity means no limit rather than no requests. That direction is
// deliberate: a client record written before limits were configured, or one
// whose limit was cleared, must not silently stop working - a limiter that
// fails closed on a missing number takes a customer offline for a
// configuration gap.
func (r RateLimit) Unlimited() bool { return r.Capacity <= 0 || r.PerSecond <= 0 }

// Validate reports whether the limit is usable.
func (r RateLimit) Validate() error {
	if r.Capacity < 0 {
		return fmt.Errorf("app: rate limit capacity must not be negative, got %d", r.Capacity)
	}

	if r.PerSecond < 0 {
		return fmt.Errorf("app: rate limit rate must not be negative, got %g", r.PerSecond)
	}

	if r.Capacity > 0 && r.PerSecond == 0 {
		return errors.New(
			"app: a rate limit with a capacity needs a rate, or the bucket never refills")
	}

	return nil
}

// String renders the limit for `client list`.
func (r RateLimit) String() string {
	if r.Unlimited() {
		return "unlimited"
	}

	return fmt.Sprintf("%d burst, %g/s", r.Capacity, r.PerSecond)
}

// Window returns how long a full bucket takes to refill from empty, which is
// what bounds the stored bucket's lifetime.
func (r RateLimit) Window() time.Duration {
	if r.Unlimited() {
		return 0
	}

	return time.Duration(float64(r.Capacity) / r.PerSecond * float64(time.Second))
}

// Decision is the outcome of one rate-limit check.
type Decision struct {
	// Allowed reports whether the request may proceed.
	Allowed bool

	// Remaining is the whole tokens left after the check, for the
	// X-RateLimit-Remaining header.
	Remaining int

	// RetryAfter is how long until the request would succeed, set only when
	// it was refused. §4 requires a 429 to carry Retry-After, and a limiter
	// that refused without saying when to come back leaves a client guessing
	// or hammering.
	RetryAfter time.Duration
}

// Limiter applies per-client token buckets in Valkey.
//
// Shared across replicas, as §7.1 requires: a per-replica limiter would let a
// client take its whole allowance from every replica at once, so the effective
// limit would be the configured value multiplied by the replica count. The
// backend concurrency limit is per replica and documented as multiplying;
// the rate limit is the one that must not.
type Limiter struct {
	client    valkey.Client
	namespace string
	now       func() time.Time
}

// NewLimiter returns a limiter over a Valkey store.
//
// It takes the concrete store rather than kv.Store because a token bucket is a
// read-modify-write that the interface cannot express atomically. §10.5
// anticipated exactly this: a fixed window fits kv.Increment, and anything
// better needs a script or an addition to the interface. A script is the
// smaller change, and valkeykv.PhysicalKey keeps its keys the same ones the
// store would use.
func NewLimiter(store *valkeykv.Store, namespace string, now func() time.Time) (*Limiter, error) {
	if store == nil {
		return nil, errors.New("app: a Valkey store is required for the rate limiter")
	}

	// Validated once, here, so a malformed namespace fails at startup rather
	// than on the first limited request.
	if _, err := valkeykv.PhysicalKey(namespace, "probe"); err != nil {
		return nil, err
	}

	limiter := &Limiter{client: store.Client(), namespace: namespace, now: now}
	if limiter.now == nil {
		limiter.now = time.Now
	}

	return limiter, nil
}

// MinBucketTTL bounds how long an idle bucket is kept.
//
// A bucket must outlive its own refill window, or a client idle for slightly
// longer than the window would find its bucket gone and start from full - which
// is harmless - while one idle for slightly less would find it expired
// mid-refill. Keeping it for twice the window plus a floor means the stored
// state is always either current or absent, never stale.
const MinBucketTTL = time.Minute

// Allow takes one token from a client's bucket.
func (l *Limiter) Allow(ctx context.Context, client string, limit RateLimit) (Decision, error) {
	return l.AllowN(ctx, client, limit, 1)
}

// AllowN takes cost tokens from a client's bucket.
//
// The refill, the check and the write happen inside one Lua execution. Two
// replicas checking the same client concurrently therefore cannot both see the
// same token and both take it, which a read-then-write would allow and which
// would make the limit approximately rather than actually enforced.
func (l *Limiter) AllowN(ctx context.Context, client string, limit RateLimit, cost int) (Decision, error) {
	if limit.Unlimited() {
		return Decision{Allowed: true, Remaining: math.MaxInt32}, nil
	}

	if cost <= 0 {
		cost = 1
	}

	key, err := valkeykv.PhysicalKey(l.namespace, client)
	if err != nil {
		return Decision{}, err
	}

	ttl := 2 * limit.Window()
	if ttl < MinBucketTTL {
		ttl = MinBucketTTL
	}

	args := []string{
		strconv.Itoa(limit.Capacity),
		strconv.FormatFloat(limit.PerSecond, 'f', -1, 64),
		strconv.FormatInt(l.now().UnixMilli(), 10),
		strconv.Itoa(cost),
		strconv.FormatInt(ttl.Milliseconds(), 10),
	}

	result, err := tokenBucketScript.Exec(ctx, l.client, []string{key}, args).ToArray()
	if err != nil {
		return Decision{}, fmt.Errorf("app: apply the rate limit for %s: %w", client, err)
	}

	if len(result) != 3 {
		return Decision{}, fmt.Errorf(
			"app: the rate limit script returned %d values, expected 3", len(result))
	}

	allowed, err := result[0].ToInt64()
	if err != nil {
		return Decision{}, fmt.Errorf("app: read the rate limit verdict: %w", err)
	}

	remaining, err := result[1].ToInt64()
	if err != nil {
		return Decision{}, fmt.Errorf("app: read the remaining tokens: %w", err)
	}

	retryMillis, err := result[2].ToInt64()
	if err != nil {
		return Decision{}, fmt.Errorf("app: read the retry delay: %w", err)
	}

	decision := Decision{
		Allowed:   allowed == 1,
		Remaining: int(remaining),
	}

	if !decision.Allowed {
		decision.RetryAfter = time.Duration(retryMillis) * time.Millisecond

		// Retry-After is expressed in whole seconds on the wire, so a delay
		// under a second would round to zero and invite an immediate retry
		// that fails again. One second is the floor.
		if decision.RetryAfter < time.Second {
			decision.RetryAfter = time.Second
		}
	}

	return decision, nil
}

// Reset empties a client's bucket state, so the next request starts from full.
//
// For `client remove` and for an operator unblocking a customer who tripped a
// limit that has since been raised - without it, the old bucket would keep
// refusing until it refilled at the old rate.
func (l *Limiter) Reset(ctx context.Context, client string) error {
	key, err := valkeykv.PhysicalKey(l.namespace, client)
	if err != nil {
		return err
	}

	if err := l.client.Do(ctx, l.client.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("app: reset the rate limit for %s: %w", client, err)
	}

	return nil
}

// tokenBucketScript refills and takes from a bucket in one execution.
//
// The bucket is a hash of two fields - the tokens left and when they were last
// counted - and the refill is computed from elapsed time rather than driven by
// a timer. That is what makes it correct across replicas and across restarts:
// there is no background process to keep running, and a bucket nobody touched
// for an hour is indistinguishable from one that was refilled all along.
//
// A clock that goes backwards is clamped to zero elapsed rather than
// subtracting tokens. Replicas' clocks differ by milliseconds in practice, and
// a limiter that punished a client for being served by the replica with the
// slower clock would be unexplainable from the outside.
var tokenBucketScript = valkey.NewLuaScript(`
local capacity = tonumber(ARGV[1])
local rate     = tonumber(ARGV[2])
local now      = tonumber(ARGV[3])
local cost     = tonumber(ARGV[4])
local ttl      = tonumber(ARGV[5])

local state  = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts     = tonumber(state[2])

if tokens == nil or ts == nil then
  tokens = capacity
  ts     = now
end

local elapsed = now - ts
if elapsed < 0 then
  elapsed = 0
end

tokens = tokens + (elapsed / 1000.0) * rate
if tokens > capacity then
  tokens = capacity
end

local allowed = 0
local retry   = 0

if tokens >= cost then
  tokens  = tokens - cost
  allowed = 1
else
  retry = math.ceil(((cost - tokens) / rate) * 1000)
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', KEYS[1], ttl)

return {allowed, math.floor(tokens), retry}
`)
