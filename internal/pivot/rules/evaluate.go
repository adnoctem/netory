package rules

import "time"

// Outcome is why a request was allowed or denied.
type Outcome string

// The possible outcomes. Each one is a distinct answer an operator can act on,
// which is why "denied" is not one value: "a rule denied this" and "no rule
// allowed this" lead to different fixes.
const (
	// OutcomeAllowed means an allow rule matched and no deny rule did.
	OutcomeAllowed Outcome = "allowed"

	// OutcomeDenied means a deny rule matched.
	OutcomeDenied Outcome = "denied"

	// OutcomeNoMatch means nothing matched, so deny-by-default applied.
	OutcomeNoMatch Outcome = "no-match"

	// OutcomeMethodRefused means the method is one pivot never forwards. It
	// is not a rule decision at all - no rule set can produce or prevent it.
	OutcomeMethodRefused Outcome = "method-refused"
)

// Allowed reports whether the outcome permits the request.
func (o Outcome) Allowed() bool { return o == OutcomeAllowed }

// Decision is the result of evaluating one request.
type Decision struct {
	// Outcome is the verdict.
	Outcome Outcome

	// Rule describes the rule that decided, empty when none did. It goes into
	// the audit entry, which is what makes "why was this denied" answerable
	// from the log rather than by re-reading the rule file against the path.
	Rule string

	// Scope records whether the deciding rule was global or the client's.
	Scope Scope
}

// Allowed reports whether the request may proceed.
func (d Decision) Allowed() bool { return d.Outcome.Allowed() }

// Evaluate applies the rule set to a method and an already-normalized path.
//
// The order is deny, then allow, then deny-by-default, exactly as §2 states.
// Deny first is what makes a deny rule unconditional: were allow evaluated
// first and allowed to win, the question "is this path denied" would depend on
// the order two lists happened to be written in.
//
// The path must already be normalized. Evaluate does not normalize, because a
// caller that passed a raw path and got an answer would have matched a rule
// against a different string from the one pivot forwards - the precise failure
// §2 exists to prevent. The pipeline normalizes once, at the top.
func (s *Set) Evaluate(method, normalizedPath string) Decision {
	if !IsForwardable(method) {
		return Decision{Outcome: OutcomeMethodRefused}
	}

	for _, rule := range s.deny {
		if rule.matches(method, normalizedPath) {
			return Decision{
				Outcome: OutcomeDenied,
				Rule:    rule.describe(),
				Scope:   rule.scope,
			}
		}
	}

	for _, rule := range s.allow {
		if rule.matches(method, normalizedPath) {
			return Decision{
				Outcome: OutcomeAllowed,
				Rule:    rule.describe(),
				Scope:   rule.scope,
			}
		}
	}

	return Decision{Outcome: OutcomeNoMatch}
}

// CacheFor returns the caching configuration for a request, if any route
// covers it.
func (s *Set) CacheFor(method, normalizedPath string) (Cache, bool) {
	for _, route := range s.routes {
		if route.matches(method, normalizedPath) {
			if route.route.Cache.TTL <= 0 {
				return Cache{}, false
			}

			return route.route.Cache, true
		}
	}

	return Cache{}, false
}

// Describe renders every rule for `rules list`, deny list first.
func (s *Set) Describe() []string {
	out := make([]string, 0, len(s.deny)+len(s.allow))

	for _, rule := range s.deny {
		out = append(out, "deny  "+rule.describe())
	}

	for _, rule := range s.allow {
		out = append(out, "allow "+rule.describe())
	}

	return out
}

// Counts returns how many deny rules, allow rules and cacheable routes the set
// holds, for `rules list` and the startup log.
func (s *Set) Counts() (deny, allow, routes int) {
	return len(s.deny), len(s.allow), len(s.routes)
}

// Empty reports whether the set has no allow rules, which means it permits
// nothing. Worth saying out loud at startup: an instance with a deny list and
// no allow list answers 403 to everything and looks broken rather than
// configured.
func (s *Set) Empty() bool { return len(s.allow) == 0 }

// Merge combines a global rule set with one client's additions.
//
// This is §10.2's model, and it is strictly accumulative: the deny lists are
// concatenated and the allow lists are concatenated, so a client's rules can
// add permissions the global set does not grant and can add restrictions of
// their own - but a client rule can never reopen a path the global set denies.
//
// Max asked whether a per-client exception to a global deny would be useful.
// It is deliberately not offered. The global deny list is the reviewed
// statement of what this instance will never serve, and an override makes that
// statement conditional on a per-customer record nobody re-reads: the failure
// is silent, affects one customer, and is invisible in the global list. With
// accumulation only, "what can this customer reach" is answered by reading two
// lists under a fixed precedence. An operator who genuinely needs an exception
// narrows the global deny and adds the broader restriction to the other
// clients, which leaves the intent visible in the configuration rather than
// buried in a flag.
//
// Deny rules go first in the merged deny list so that a global deny is
// evaluated before a client one. It makes no difference to the verdict -
// either match denies - but it means the audit entry names the global rule
// when both match, which is the one an operator needs to see.
func Merge(global, client *Set) *Set {
	switch {
	case global == nil && client == nil:
		return &Set{scope: ScopeGlobal}
	case client == nil:
		return global
	case global == nil:
		return client
	}

	merged := &Set{scope: ScopeClient}

	merged.deny = concat(global.deny, client.deny)
	merged.allow = concat(global.allow, client.allow)

	// Client routes come first, so a client-specific cache TTL overrides the
	// global one for that path. Caching is not an access-control decision -
	// the rules have already allowed the request by the time a route is
	// consulted - so first-match-wins here costs nothing and lets an operator
	// shorten one customer's TTL without touching the global set.
	merged.routes = concat(client.routes, global.routes)

	return merged
}

// concat joins two slices into a new one, so neither input is aliased into the
// result. A merged set that shared backing arrays with a global set would be a
// reload mutating a live client set.
func concat[T any](first, second []T) []T {
	if len(first) == 0 && len(second) == 0 {
		return nil
	}

	out := make([]T, 0, len(first)+len(second))
	out = append(out, first...)
	out = append(out, second...)

	return out
}

// EmptyDocument returns a document that permits nothing, which is what an
// instance with no rules loaded enforces.
func EmptyDocument() Document { return Document{} }

// EmptySet returns a compiled set that permits nothing.
//
// Used before the first rule load and whenever a reload fails: a pivot that
// cannot read its rules denies everything rather than serving without them.
// That is the only safe direction for a service whose job is to refuse.
func EmptySet() *Set { return &Set{scope: ScopeGlobal} }

// CacheTTL is a convenience for the pipeline: the TTL for a request, or zero
// when the route is not cacheable.
func (s *Set) CacheTTL(method, normalizedPath string) time.Duration {
	cache, ok := s.CacheFor(method, normalizedPath)
	if !ok {
		return 0
	}

	return cache.TTL
}
