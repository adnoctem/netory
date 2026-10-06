package app

import (
	"strconv"

	"github.com/adnoctem/netory/pkg/event"
)

// protean's event taxonomy, as section 8.1 defines it.
//
// The constants live here rather than in pkg/event because each service has its
// own taxonomy and the shared package stays agnostic about them.
const (
	// EventHostUpdated fires when an address change is written to the
	// provider. A `nochg` does not fire it: nothing happened.
	EventHostUpdated = event.Type("host.updated")

	// EventHostUpdateFailed fires when a provider call failed.
	EventHostUpdateFailed = event.Type("host.update_failed")

	// EventAuthFailed fires on repeated authentication failures for a host or
	// source address - not on a single one, which is a typo rather than an
	// incident.
	EventAuthFailed = event.Type("auth.failed")

	// EventTokenCreated and EventTokenRevoked record token lifecycle changes
	// made through the CLI.
	EventTokenCreated = event.Type("token.created")
	EventTokenRevoked = event.Type("token.revoked")

	// EventProviderFailed fires when a provider is unreachable or its
	// credentials are rejected.
	EventProviderFailed = event.Type("provider.failed")
)

// EventTypes lists every event protean emits, for `notifier` documentation and
// for a test that asserts the taxonomy matches the design document.
func EventTypes() []event.Type {
	return []event.Type{
		EventHostUpdated,
		EventHostUpdateFailed,
		EventAuthFailed,
		EventTokenCreated,
		EventTokenRevoked,
		EventProviderFailed,
	}
}

// HostUpdated builds the event for a successful address write.
func HostUpdated(host, ipv4, ipv6 string) event.Event {
	e := event.New(EventHostUpdated, host, "address updated at the DNS provider")

	if ipv4 != "" {
		e = e.WithField("ipv4", ipv4)
	}

	if ipv6 != "" {
		e = e.WithField("ipv6", ipv6)
	}

	return e
}

// HostUpdateFailed builds the event for a failed provider write.
func HostUpdateFailed(host, providerName string, cause error) event.Event {
	e := event.New(EventHostUpdateFailed, host, "could not update the DNS provider").
		WithField("provider", providerName)

	if cause != nil {
		e = e.WithField("error", cause.Error())
	}

	return e
}

// AuthFailed builds the event for repeated authentication failures.
//
// The subject is whatever was being attacked - a hostname or a source address.
// Both are attacker-supplied, which is precisely why pkg/notify strips CR and
// LF from every header value it builds from event data.
func AuthFailed(subject, source string, failures int) event.Event {
	e := event.New(EventAuthFailed, subject, "repeated authentication failures").
		WithField("failures", strconv.Itoa(failures))

	if source != "" {
		e = e.WithField("source", source)
	}

	return e
}

// TokenCreated builds the event for a token being issued.
func TokenCreated(host, tokenID, by string) event.Event {
	return event.New(EventTokenCreated, host, "a token was issued").
		WithField("token_id", tokenID).
		WithField("by", by)
}

// TokenRevoked builds the event for a token being revoked.
func TokenRevoked(host, tokenID, by string) event.Event {
	return event.New(EventTokenRevoked, host, "a token was revoked").
		WithField("token_id", tokenID).
		WithField("by", by)
}

// ProviderFailed builds the event for a provider being unreachable or
// rejecting its credentials.
func ProviderFailed(providerName string, cause error) event.Event {
	e := event.New(EventProviderFailed, providerName, "the DNS provider rejected the request")

	if cause != nil {
		e = e.WithField("error", cause.Error())
	}

	return e
}
