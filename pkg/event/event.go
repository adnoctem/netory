// Package event is the typed event bus and persistent outbox shared by
// protean, signpost and pivot.
//
// All three services promise that nothing is lost on restart: an event is
// persisted before any delivery is attempted, so a process restart or a relay
// outage delays a notification rather than dropping it. That promise is the
// reason this package exists at all - an in-process channel fan-out would be a
// dozen lines and would lose everything in flight on SIGTERM.
//
// # The shape of the guarantee
//
// Delivery is at-least-once, not exactly-once. An event is marked delivered
// only after a notifier reports success, so a crash between a successful send
// and the mark means the event is retried and the notification arrives twice.
// The alternative - marking first - turns the same crash into a notification
// that never arrives, and for an alert about a failing DNS update a duplicate
// is a nuisance where a silence is a fault.
//
// # Why the outbox is not just a queue
//
// Events describe things that already happened, so the outbox is append-only
// and an entry's lifecycle is pending -> delivered, or pending -> dead after
// MaxAttempts. Nothing re-orders it and nothing deletes a pending entry except
// delivery, which is what makes a restart able to pick up exactly where it left
// off by scanning for pending entries.
package event

import (
	"errors"
	"strings"
	"time"
)

// Type identifies what happened. Each service declares its own constants - the
// taxonomies are in protean section 8.1, signpost section 7.2 and pivot
// section 8.3 - so this package stays agnostic about them.
type Type string

// Event is something that happened, recorded for delivery.
type Event struct {
	// ID is unique and sorts chronologically, so scanning the outbox by key
	// prefix yields events in roughly the order they occurred without a
	// secondary index.
	ID string `json:"id"`

	// Type is what happened.
	Type Type `json:"type"`

	// OccurredAt is when it happened, in UTC.
	OccurredAt time.Time `json:"occurred_at"`

	// Subject is what it happened to - a hostname, a release version, a client
	// ID. It is the one field a notifier can reliably put in a subject line.
	Subject string `json:"subject,omitempty"`

	// Message is a short human-readable summary.
	Message string `json:"message,omitempty"`

	// Fields carries structured detail. Values come from request data in some
	// cases - a hostname from a failed authentication attempt, for instance -
	// so a consumer rendering them into a protocol with its own framing must
	// sanitise them. pkg/notify's SMTP transport is where that matters.
	Fields map[string]string `json:"fields,omitempty"`
}

// New builds an Event with a generated ID and the current time.
func New(typ Type, subject, message string) Event {
	return Event{
		ID:         NewID(time.Now()),
		Type:       typ,
		OccurredAt: time.Now().UTC(),
		Subject:    subject,
		Message:    message,
	}
}

// WithField returns a copy of e with one field set. It copies rather than
// mutating, so an Event handed to several notifiers cannot be changed under
// one of them.
func (e Event) WithField(key, value string) Event {
	fields := make(map[string]string, len(e.Fields)+1)
	for k, v := range e.Fields {
		fields[k] = v
	}
	fields[key] = value

	out := e
	out.Fields = fields

	return out
}

// WithFields returns a copy of e with several fields set.
func (e Event) WithFields(fields map[string]string) Event {
	out := e
	for k, v := range fields {
		out = out.WithField(k, v)
	}

	return out
}

// Field returns the value of a field, or "".
func (e Event) Field(key string) string { return e.Fields[key] }

// String renders the event for a log line.
func (e Event) String() string {
	var b strings.Builder

	b.WriteString(string(e.Type))
	if e.Subject != "" {
		b.WriteString(" ")
		b.WriteString(e.Subject)
	}
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}

	return b.String()
}

// Validate reports whether the event is well-formed enough to persist.
func (e Event) Validate() error {
	if e.ID == "" {
		return errors.New("event: ID is empty")
	}

	if e.Type == "" {
		return errors.New("event: type is empty")
	}

	if e.OccurredAt.IsZero() {
		return errors.New("event: OccurredAt is zero")
	}

	return nil
}
