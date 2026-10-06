package notify

import (
	"fmt"
	"mime"
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/adnoctem/netory/pkg/event"
)

// sanitizeHeader removes CR and LF from a header value.
//
// This is the control that stops an event field from becoming an extra SMTP
// header. Event payloads carry attacker-influenced values - the hostname from
// a failed authentication attempt is the clearest case - and a value containing
// "\r\nBcc: someone@example.invalid" would, concatenated into a message, create
// a real Bcc header. Stripping the line breaks is not a formality; it is the
// whole defence.
//
// mime.QEncoding would also neutralise these characters, encoding them as =0D
// and =0A, but only when it encodes at all: a plain-ASCII value is returned
// untouched, and only the Subject is encoded in the first place. So every
// header value passes through here regardless.
func sanitizeHeader(value string) string {
	// The CRLF pair is collapsed before the individual characters, so an
	// injected "\r\n" becomes one space rather than two. Cosmetic only - the
	// safety comes from there being no line break left either way.
	value = strings.ReplaceAll(value, "\r\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")

	// A NUL would truncate the header in some downstream parsers, and a lone
	// tab or space run at the edges is noise.
	value = strings.ReplaceAll(value, "\x00", "")

	return strings.TrimSpace(value)
}

// encodeSubject sanitises and then RFC 2047-encodes a subject line, so a
// non-ASCII subject survives and an injected line break does not.
func encodeSubject(subject string) string {
	return mime.QEncoding.Encode("utf-8", sanitizeHeader(subject))
}

// validateAddress rejects a malformed mail address.
//
// Addresses come from configuration rather than from events, so this is a
// configuration-time check: catching it when the notifier is added turns what
// would be a permanent, silent notification outage into an error message at
// `notifier add`.
func validateAddress(addr string) error {
	parsed, err := mail.ParseAddress(addr)
	if err != nil {
		return fmt.Errorf("%q is not a valid mail address: %w", addr, err)
	}

	// An address that survived parsing but still contains a line break would
	// be an injection vector in the envelope rather than the headers.
	if sanitizeHeader(parsed.Address) != parsed.Address {
		return fmt.Errorf("%q contains a line break", addr)
	}

	return nil
}

// compose renders an event as an RFC 5322 message.
func (s *smtpNotifier) compose(e event.Event) ([]byte, error) {
	var b strings.Builder

	// Headers. Every value is sanitised, including the ones that look like
	// they could not possibly contain a line break: the from and to addresses
	// were validated at configuration time, and the rest derive from event
	// data.
	headers := [][2]string{
		{"From", sanitizeHeader(s.from)},
		{"To", sanitizeHeader(strings.Join(s.to, ", "))},
		{"Subject", encodeSubject(subjectFor(e))},
		{"Date", e.OccurredAt.Format(time.RFC1123Z)},
		{"Message-ID", messageID(e, s.host)},
		{"MIME-Version", "1.0"},
		{"Content-Type", `text/plain; charset="utf-8"`},
		{"Content-Transfer-Encoding", "8bit"},

		// The event type and ID as headers, so an operator can filter mail by
		// them. Both are sanitised like everything else - the type is a
		// compiled-in constant, but the ID comes through the outbox and this
		// code should not depend on which of its inputs happen to be trusted.
		{"X-Netory-Event", sanitizeHeader(string(e.Type))},
		{"X-Netory-Event-ID", sanitizeHeader(e.ID)},
	}

	for _, header := range headers {
		if header[1] == "" {
			continue
		}

		b.WriteString(header[0])
		b.WriteString(": ")
		b.WriteString(header[1])
		b.WriteString("\r\n")
	}

	b.WriteString("\r\n")
	b.WriteString(body(e))

	return []byte(b.String()), nil
}

// subjectFor builds a subject line from an event.
func subjectFor(e event.Event) string {
	if e.Subject == "" {
		return string(e.Type)
	}

	return string(e.Type) + ": " + e.Subject
}

// messageID builds an RFC 5322 Message-ID from the event ID, which is already
// unique. Using it means a relay or mail client that deduplicates by
// Message-ID will collapse the duplicate that at-least-once delivery can
// produce - the outbox's retry becomes invisible rather than a second mail.
func messageID(e event.Event, host string) string {
	id := sanitizeHeader(e.ID)
	domain := sanitizeHeader(host)
	if id == "" || domain == "" {
		return ""
	}

	return "<" + id + "@" + domain + ">"
}

// body renders the message body.
//
// The body is not a header, so a line break in a field is harmless here - but
// the fields are still rendered one per line with a sorted, stable order, so
// that two notifications about the same kind of event are diffable.
func body(e event.Event) string {
	var b strings.Builder

	if e.Message != "" {
		b.WriteString(e.Message)
		b.WriteString("\r\n\r\n")
	}

	b.WriteString("Event:    ")
	b.WriteString(string(e.Type))
	b.WriteString("\r\n")

	if e.Subject != "" {
		b.WriteString("Subject:  ")
		b.WriteString(e.Subject)
		b.WriteString("\r\n")
	}

	b.WriteString("Occurred: ")
	b.WriteString(e.OccurredAt.Format(time.RFC3339))
	b.WriteString("\r\n")

	b.WriteString("ID:       ")
	b.WriteString(e.ID)
	b.WriteString("\r\n")

	if len(e.Fields) > 0 {
		keys := make([]string, 0, len(e.Fields))
		for key := range e.Fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		b.WriteString("\r\n")
		for _, key := range keys {
			b.WriteString(key)
			b.WriteString(": ")

			// Line breaks in a field value would make the body ambiguous to
			// read, though not unsafe. Replaced for legibility, not security.
			b.WriteString(strings.ReplaceAll(strings.ReplaceAll(e.Fields[key], "\r", " "), "\n", " "))
			b.WriteString("\r\n")
		}
	}

	return b.String()
}
