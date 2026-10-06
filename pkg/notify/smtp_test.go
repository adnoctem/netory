package notify_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/notify"
)

func newSMTPNotifier(t *testing.T, settings map[string]string) notify.Notifier {
	t.Helper()

	base := map[string]string{
		notify.SettingHost: "smtp.example.org",
		notify.SettingFrom: "protean@example.org",
		notify.SettingTo:   "ops@example.org",
	}
	for k, v := range settings {
		base[k] = v
	}

	notifier, err := notify.New(notify.Config{Name: "ops-mail", Kind: notify.KindSMTP, Settings: base}, testSecret(t))
	require.NoError(t, err)

	return notifier
}

func TestSanitizeHeaderRemovesLineBreaks(t *testing.T) {
	asrt := assert.New(t)

	for input, want := range map[string]string{
		"plain value":                    "plain value",
		"with\rcarriage":                 "with carriage",
		"with\nnewline":                  "with newline",
		"with\r\nboth":                   "with both",
		"\r\nleading":                    "leading",
		"trailing\r\n":                   "trailing",
		"nul\x00byte":                    "nulbyte",
		"host\r\nBcc: a@example.invalid": "host Bcc: a@example.invalid",
	} {
		got := notify.SanitizeHeaderForTest(input)
		asrt.Equal(want, got, "input %q", input)
		asrt.NotContains(got, "\r")
		asrt.NotContains(got, "\n")
	}
}

// The subject is both sanitised and RFC 2047-encoded. Encoding alone is not
// enough, because mime.QEncoding returns a plain-ASCII value untouched.
func TestEncodeSubjectIsSafeAndPreservesNonASCII(t *testing.T) {
	asrt := assert.New(t)

	injected := notify.EncodeSubjectForTest("host updated\r\nBcc: attacker@example.invalid")
	asrt.NotContains(injected, "\r")
	asrt.NotContains(injected, "\n")

	// Non-ASCII survives, encoded.
	unicode := notify.EncodeSubjectForTest("Grüße aus München")
	asrt.NotContains(unicode, "\r")
	asrt.Contains(unicode, "=?utf-8?q?")

	// Plain ASCII is left readable rather than needlessly encoded.
	asrt.Equal("host.updated: example.org", notify.EncodeSubjectForTest("host.updated: example.org"))
}

// The load-bearing security test for this transport. Event payloads carry
// attacker-influenced values - a hostname from a failed authentication attempt
// - and a line break in one must not become a real header.
func TestComposeResistsHeaderInjection(t *testing.T) {
	asrt := assert.New(t)
	notifier := newSMTPNotifier(t, nil)

	hostile := event.Event{
		ID:         "id\r\nX-Injected-Via-ID: yes",
		Type:       event.Type("auth.failed\r\nX-Injected-Via-Type: yes"),
		OccurredAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		Subject:    "evil.example\r\nBcc: attacker@example.invalid",
		Message:    "repeated bad token",
	}

	message, err := notify.ComposeForTest(notifier, hostile)
	require.NoError(t, err)

	text := string(message)
	headerBlock, _, found := strings.Cut(text, "\r\n\r\n")
	require.True(t, found, "the message must have a header/body separator")

	// The property that matters is that no *line* begins with a header the
	// attacker named. The neutralised text still contains the substring
	// "Bcc:", because it survives inside the Subject value - which is correct:
	// the hostname is evidence and belongs in the alert. What must not exist
	// is a line starting with it.
	lines := strings.Split(headerBlock, "\r\n")
	for _, line := range lines {
		for _, forged := range []string{"Bcc:", "X-Injected-Via-ID:", "X-Injected-Via-Type:"} {
			asrt.False(strings.HasPrefix(line, forged),
				"an event field forged the %s header: %q", forged, line)
		}
	}

	// Every header line must be exactly one well-formed header. Nothing here
	// folds, so a continuation line - one starting with whitespace - would
	// mean a value had broken out across a line boundary.
	expectedHeaders := []string{
		"From", "To", "Subject", "Date", "Message-ID", "MIME-Version",
		"Content-Type", "Content-Transfer-Encoding", "X-Netory-Event", "X-Netory-Event-ID",
	}
	asrt.Len(lines, len(expectedHeaders),
		"the hostile event produced %d header lines, want %d - an extra line is an injected header",
		len(lines), len(expectedHeaders))

	for i, line := range lines {
		name, _, ok := strings.Cut(line, ": ")
		require.True(t, ok, "malformed header line %q", line)
		asrt.NotContains(name, " ", "header name %q contains a space, so a value leaked into it", name)

		if i < len(expectedHeaders) {
			asrt.Equal(expectedHeaders[i], name, "header %d is not the expected one", i)
		}
	}

	// And the attacker's text is still present, neutralised rather than
	// silently dropped: the hostname is evidence and belongs in the alert.
	asrt.Contains(text, "evil.example")
}

func TestComposeProducesAWellFormedMessage(t *testing.T) {
	asrt := assert.New(t)
	notifier := newSMTPNotifier(t, map[string]string{
		notify.SettingTo: "ops@example.org, oncall@example.org",
	})

	e := event.Event{
		ID:         "0000000000000001deadbeefdeadbeef",
		Type:       event.Type("host.updated"),
		OccurredAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		Subject:    "example.org",
		Message:    "address changed",
		Fields:     map[string]string{"ip": "203.0.113.1", "family": "ipv4"},
	}

	message, err := notify.ComposeForTest(notifier, e)
	require.NoError(t, err)

	text := string(message)
	headerBlock, bodyBlock, found := strings.Cut(text, "\r\n\r\n")
	require.True(t, found)

	asrt.Contains(headerBlock, "From: protean@example.org\r\n")
	asrt.Contains(headerBlock, "To: ops@example.org, oncall@example.org\r\n")
	asrt.Contains(headerBlock, "Subject: host.updated: example.org\r\n")
	asrt.Contains(headerBlock, `Content-Type: text/plain; charset="utf-8"`)
	asrt.Contains(headerBlock, "X-Netory-Event: host.updated\r\n")
	asrt.Contains(headerBlock, "X-Netory-Event-ID: "+e.ID)

	// The Message-ID is derived from the event ID, so a relay that
	// deduplicates by it collapses the duplicate at-least-once delivery can
	// produce.
	asrt.Contains(headerBlock, "Message-ID: <"+e.ID+"@smtp.example.org>\r\n")

	asrt.Contains(bodyBlock, "address changed")
	asrt.Contains(bodyBlock, "ID:       "+e.ID)

	// Fields are rendered in a stable sorted order, so two notifications about
	// the same kind of event are diffable.
	familyAt := strings.Index(bodyBlock, "family: ipv4")
	ipAt := strings.Index(bodyBlock, "ip: 203.0.113.1")
	asrt.Positive(familyAt)
	asrt.Positive(ipAt)
	asrt.Less(familyAt, ipAt, "fields must be sorted by key")
}

// A relay that cannot upgrade to TLS must be refused, not silently used in
// cleartext: the relay password and the event contents both travel it.
func TestSMTPRefusesARelayWithoutSTARTTLS(t *testing.T) {
	asrt := assert.New(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	// A minimal SMTP greeting and EHLO response that advertises no STARTTLS.
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		reader := bufio.NewReader(conn)
		_, _ = fmt.Fprint(conn, "220 relay.example.org ESMTP\r\n")

		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}

			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				// 8BITMIME only - deliberately no STARTTLS.
				_, _ = fmt.Fprint(conn, "250-relay.example.org\r\n250 8BITMIME\r\n")
			case strings.HasPrefix(line, "QUIT"):
				_, _ = fmt.Fprint(conn, "221 bye\r\n")

				return
			default:
				_, _ = fmt.Fprint(conn, "250 ok\r\n")
			}
		}
	}()

	host, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	notifier := newSMTPNotifier(t, map[string]string{
		notify.SettingHost: host,
		notify.SettingPort: port,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = notifier.Deliver(ctx, event.New(event.Type("host.updated"), "example.org", "changed"))
	asrt.Error(err)
	asrt.Contains(err.Error(), "STARTTLS")
	asrt.Contains(err.Error(), "refusing to send in cleartext")
}

// A relay that is not listening at all is a delivery failure the outbox will
// retry, not a panic.
func TestSMTPReportsAnUnreachableRelay(t *testing.T) {
	asrt := assert.New(t)

	// Port 1 on loopback: reliably refused and never a real relay.
	notifier := newSMTPNotifier(t, map[string]string{
		notify.SettingHost: "127.0.0.1",
		notify.SettingPort: "1",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := notifier.Deliver(ctx, event.New(event.Type("host.updated"), "example.org", "changed"))
	asrt.Error(err)
	asrt.Contains(err.Error(), "ops-mail", "the error must name which notifier failed")
}

func TestSMTPKindAndName(t *testing.T) {
	asrt := assert.New(t)
	notifier := newSMTPNotifier(t, nil)

	asrt.Equal("ops-mail", notifier.Name())
	asrt.Equal(notify.KindSMTP, notifier.Kind())
}
