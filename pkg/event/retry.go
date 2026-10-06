package event

import (
	"math"
	"math/rand/v2"
	"time"
)

// RetryPolicy governs how a failed delivery is retried.
type RetryPolicy struct {
	// MaxAttempts is how many attempts are made before an entry is abandoned.
	MaxAttempts int

	// BaseDelay is the delay after the first failure.
	BaseDelay time.Duration

	// MaxDelay caps the backoff.
	MaxDelay time.Duration

	// Jitter is the fraction of the computed delay that is randomised, between
	// 0 and 1.
	Jitter float64
}

// DefaultRetryPolicy is the policy all three services use unless an operator
// overrides it.
//
// Ten attempts over an hour-capped exponential backoff covers the failure this
// is actually for: an SMTP relay or webhook receiver being down for a while.
// Abandoning after ten attempts rather than retrying forever is deliberate - an
// endpoint that has refused ten times over several hours is misconfigured, not
// busy, and an unbounded queue of events for it would grow until the disk did.
var DefaultRetryPolicy = RetryPolicy{
	MaxAttempts: 10,
	BaseDelay:   30 * time.Second,
	MaxDelay:    time.Hour,
	Jitter:      0.2,
}

// Backoff returns the delay before the next attempt, given how many attempts
// have already failed.
//
// Exponential with jitter. The jitter is not decoration: a flapping connection
// produces a burst of events that all fail together and would otherwise retry
// in lockstep forever, hammering the relay in synchronised waves. Spreading
// them is what turns that into a trickle.
func (p RetryPolicy) Backoff(attempts int) time.Duration {
	base := p.BaseDelay
	if base <= 0 {
		base = DefaultRetryPolicy.BaseDelay
	}

	maxDelay := p.MaxDelay
	if maxDelay <= 0 {
		maxDelay = DefaultRetryPolicy.MaxDelay
	}

	if attempts < 1 {
		attempts = 1
	}

	// Compute in float64 and clamp before converting: 30s shifted left 60
	// times overflows int64 and would come out negative, which would schedule
	// the retry in the past and spin.
	delay := float64(base) * math.Pow(2, float64(attempts-1))
	if delay > float64(maxDelay) {
		delay = float64(maxDelay)
	}

	jitter := p.Jitter
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 1 {
		jitter = 1
	}

	if jitter > 0 {
		// Jitter downwards only, so the delay stays within MaxDelay and a
		// configured cap means what it says.
		delay -= delay * jitter * rand.Float64()
	}

	if delay < 0 {
		delay = 0
	}

	return time.Duration(delay)
}

// Normalise returns the policy with unset fields replaced by the defaults, so a
// partially-specified configuration is still usable.
//
// Every field treats its zero value as unset, Jitter included. That makes
// Jitter: 0 mean "not configured" rather than "no jitter", which is the right
// reading for a configuration file that simply omits the key - and the wrong
// one for a caller that genuinely wants deterministic backoff. Such a caller
// passes its policy straight to Backoff instead of through Normalise, which is
// what the tests here do; there is no in-band way to say "exactly zero"
// without a *float64, and a pointer in a configuration struct is a worse trade
// than this sentence.
func (p RetryPolicy) Normalise() RetryPolicy {
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = DefaultRetryPolicy.MaxAttempts
	}
	if p.BaseDelay <= 0 {
		p.BaseDelay = DefaultRetryPolicy.BaseDelay
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = DefaultRetryPolicy.MaxDelay
	}
	if p.Jitter <= 0 || p.Jitter > 1 {
		p.Jitter = DefaultRetryPolicy.Jitter
	}

	return p
}
