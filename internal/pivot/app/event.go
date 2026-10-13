package app

import (
	"strconv"

	"github.com/adnoctem/netory/pkg/event"
)

// pivot's event taxonomy, as docs/ARCHITECTURE.md documents it.
//
// Every one of these is either an aggregate or an incident. There is
// deliberately no per-request event: pivot's proxy listener carries whatever
// volume customers send, so an event per request would be a
// denial-of-service amplifier pointed at the operator's mailbox - the same
// reasoning signpost's taxonomy records, and it applies harder here because
// pivot sees more traffic.
const (
	// EventClientAuthFailed fires on repeated failed authentication for one
	// client or source address - not on a single failure, which is a
	// misconfigured client rather than an incident.
	EventClientAuthFailed = event.Type("client.auth_failed")

	// EventRuleDenied fires when requests are denied by a rule, aggregated.
	//
	// Aggregated because a client pointed at the wrong path retries, and one
	// mail per retry would bury the signal. The threshold is a setting.
	EventRuleDenied = event.Type("rule.denied")

	// EventClientRateLimited fires when a client exceeds its limit,
	// aggregated for the same reason.
	EventClientRateLimited = event.Type("client.rate_limited")

	// EventBackendFailed fires when backend errors or timeouts pass a
	// threshold. This is the one an operator most wants: it means the thing
	// pivot is shielding is in trouble.
	EventBackendFailed = event.Type("backend.failed")

	// EventBackendAuthFailed fires when the backend rejects pivot's own
	// credentials. Distinct from backend.failed because it will not fix
	// itself: a rotated integration secret or a revoked ACL role needs a
	// person.
	EventBackendAuthFailed = event.Type("backend.auth_failed")
)

// EventTypes lists every event pivot emits, for `notifier` help text and for
// the test that asserts the taxonomy matches the documented one.
func EventTypes() []event.Type {
	return []event.Type{
		EventClientAuthFailed,
		EventRuleDenied,
		EventClientRateLimited,
		EventBackendFailed,
		EventBackendAuthFailed,
	}
}

// ClientAuthFailed builds the event for repeated authentication failures.
//
// The subject is whatever was being attacked - a client id or a source
// address. Both are attacker-supplied, which is precisely why pkg/notify
// strips CR and LF from every header value it builds from event data.
func ClientAuthFailed(subject, source string, failures int) event.Event {
	e := event.New(EventClientAuthFailed, subject, "repeated authentication failures").
		WithField("failures", strconv.Itoa(failures))

	if source != "" {
		e = e.WithField("source", source)
	}

	return e
}

// RuleDenied builds the aggregated rule-denial event.
//
// It carries one example path rather than all of them. The alternative is an
// unbounded field built from request data, which is both a notification nobody
// reads and a way to put a lot of attacker-chosen text into a mail.
func RuleDenied(client string, denials int, examplePath, rule string) event.Event {
	e := event.New(EventRuleDenied, client, "requests denied by a path rule").
		WithField("denials", strconv.Itoa(denials)).
		WithField("example_path", examplePath)

	if rule != "" {
		e = e.WithField("rule", rule)
	}

	return e
}

// ClientRateLimited builds the aggregated rate-limit event.
func ClientRateLimited(client string, refusals int) event.Event {
	return event.New(EventClientRateLimited, client, "a client exceeded its rate limit").
		WithField("refusals", strconv.Itoa(refusals))
}

// BackendFailed builds the event for backend errors above the threshold.
func BackendFailed(backend string, failures int, cause error) event.Event {
	e := event.New(EventBackendFailed, backend, "the backend is failing requests").
		WithField("failures", strconv.Itoa(failures))

	if cause != nil {
		e = e.WithField("error", cause.Error())
	}

	return e
}

// BackendAuthFailed builds the event for the backend rejecting pivot.
func BackendAuthFailed(client string, cause error) event.Event {
	e := event.New(EventBackendAuthFailed, client,
		"the backend rejected pivot's own credentials for this client")

	if cause != nil {
		e = e.WithField("error", cause.Error())
	}

	return e
}
