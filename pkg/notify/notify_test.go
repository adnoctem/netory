package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/notify"
	"github.com/adnoctem/netory/pkg/secret"
)

func testSecret(t *testing.T) *secret.Secret {
	t.Helper()

	raw, err := secret.Generate()
	require.NoError(t, err)

	sec, err := secret.Parse(raw)
	require.NoError(t, err)

	return sec
}

func TestKindsAreRegistered(t *testing.T) {
	asrt := assert.New(t)

	// Transports are compiled in and registered at init, so both are present
	// without any wiring by the caller.
	asrt.Equal([]string{notify.KindSMTP, notify.KindWebhook}, notify.Kinds())
}

func TestNewRejectsUnknownKind(t *testing.T) {
	asrt := assert.New(t)

	_, err := notify.New(notify.Config{Name: "ops", Kind: "telegram"}, testSecret(t))
	asrt.ErrorIs(err, notify.ErrUnknownKind)

	// The message names what is available, since the whole point of
	// compiled-in transports is that the list is fixed at build time.
	asrt.Contains(err.Error(), notify.KindSMTP)
	asrt.Contains(err.Error(), notify.KindWebhook)
}

func TestNewRequiresAName(t *testing.T) {
	_, err := notify.New(notify.Config{Kind: notify.KindSMTP}, testSecret(t))
	assert.Error(t, err)
}

// `notifier list` must never print a credential (protean section 8.3).
func TestRedactedHidesSecrets(t *testing.T) {
	asrt := assert.New(t)

	cfg := notify.Config{
		Name: "ops-mail",
		Kind: notify.KindSMTP,
		Settings: map[string]string{
			notify.SettingHost:     "smtp.example.org",
			notify.SettingUsername: "protean@example.org",
			notify.SettingPassword: "hunter2-the-real-password",
			notify.SettingFrom:     "protean@example.org",
			notify.SettingTo:       "ops@example.org",
		},
	}

	redacted := cfg.Redacted()
	asrt.Equal("smtp.example.org", redacted[notify.SettingHost])
	asrt.Equal("protean@example.org", redacted[notify.SettingUsername],
		"the username is not a credential on its own and is operationally useful")

	// "(set)" rather than omitted: "configured" and "never set" are different
	// diagnoses for the same symptom.
	asrt.Equal("(set)", redacted[notify.SettingPassword])

	for key, value := range redacted {
		asrt.NotContains(value, "hunter2", "the password leaked through %q", key)
	}

	// An unset secret is omitted entirely rather than shown as "(set)".
	cfg.Settings[notify.SettingPassword] = ""
	asrt.NotContains(cfg.Redacted(), notify.SettingPassword)
}

// A webhook URL often carries a token in its path or query.
func TestWebhookRedactsItsURL(t *testing.T) {
	asrt := assert.New(t)

	notifier, err := notify.New(notify.Config{
		Name:     "ops-hook",
		Kind:     notify.KindWebhook,
		Settings: map[string]string{notify.SettingURL: "https://hooks.example.org/t/SECRET-TOKEN-VALUE"},
	}, testSecret(t))
	require.NoError(t, err)

	redacted := notifier.Redacted()
	asrt.Equal("https://hooks.example.org/(redacted)", redacted[notify.SettingURL])

	for key, value := range redacted {
		asrt.NotContains(value, "SECRET-TOKEN-VALUE", "the URL token leaked through %q", key)
	}
}

func TestSMTPConfigValidation(t *testing.T) {
	asrt := assert.New(t)
	sec := testSecret(t)

	base := func() map[string]string {
		return map[string]string{
			notify.SettingHost: "smtp.example.org",
			notify.SettingFrom: "protean@example.org",
			notify.SettingTo:   "ops@example.org",
		}
	}

	_, err := notify.New(notify.Config{Name: "ok", Kind: notify.KindSMTP, Settings: base()}, sec)
	asrt.NoError(err)

	for name, mutate := range map[string]func(map[string]string){
		"no host":        func(s map[string]string) { delete(s, notify.SettingHost) },
		"no from":        func(s map[string]string) { delete(s, notify.SettingFrom) },
		"no to":          func(s map[string]string) { delete(s, notify.SettingTo) },
		"empty to list":  func(s map[string]string) { s[notify.SettingTo] = " , , " },
		"bad from":       func(s map[string]string) { s[notify.SettingFrom] = "not an address" },
		"bad to":         func(s map[string]string) { s[notify.SettingTo] = "ops@example.org, nope" },
		"bad port":       func(s map[string]string) { s[notify.SettingPort] = "smtp" },
		"port too large": func(s map[string]string) { s[notify.SettingPort] = "70000" },
		"port zero":      func(s map[string]string) { s[notify.SettingPort] = "0" },
	} {
		settings := base()
		mutate(settings)

		_, err := notify.New(notify.Config{Name: "x", Kind: notify.KindSMTP, Settings: settings}, sec)
		asrt.Error(err, name)
	}

	// A malformed address configured once would otherwise fail every delivery
	// forever, which an operator would read as an outage rather than a typo.
	settings := base()
	settings[notify.SettingFrom] = "protean@example.org\r\nBcc: attacker@example.invalid"
	_, err = notify.New(notify.Config{Name: "x", Kind: notify.KindSMTP, Settings: settings}, sec)
	asrt.Error(err, "an address containing a line break must be rejected at configuration time")

	// Several recipients, comma-separated, since settings are a flat map.
	settings = base()
	settings[notify.SettingTo] = "ops@example.org, oncall@example.org"
	notifier, err := notify.New(notify.Config{Name: "x", Kind: notify.KindSMTP, Settings: settings}, sec)
	asrt.NoError(err)
	asrt.Contains(notifier.Redacted()[notify.SettingTo], "oncall@example.org")
}

func TestWebhookConfigValidation(t *testing.T) {
	asrt := assert.New(t)
	sec := testSecret(t)

	for name, settings := range map[string]map[string]string{
		"no url":       {},
		"http scheme":  {notify.SettingURL: "http://hooks.example.org/t"},
		"no scheme":    {notify.SettingURL: "hooks.example.org/t"},
		"no host":      {notify.SettingURL: "https:///path"},
		"bad timeout":  {notify.SettingURL: "https://h.example.org/t", notify.SettingTimeout: "soon"},
		"zero timeout": {notify.SettingURL: "https://h.example.org/t", notify.SettingTimeout: "0s"},
	} {
		_, err := notify.New(notify.Config{Name: "x", Kind: notify.KindWebhook, Settings: settings}, sec)
		asrt.Error(err, name)
	}

	// Plain HTTP is refused, and the error says why rather than just "invalid".
	_, err := notify.New(notify.Config{
		Name:     "x",
		Kind:     notify.KindWebhook,
		Settings: map[string]string{notify.SettingURL: "http://hooks.example.org/t"},
	}, sec)
	asrt.Contains(err.Error(), "personal data")

	// A signing key cannot be derived without a secret.
	_, err = notify.New(notify.Config{
		Name:     "x",
		Kind:     notify.KindWebhook,
		Settings: map[string]string{notify.SettingURL: "https://hooks.example.org/t"},
	}, nil)
	asrt.Error(err)
}

// receivedRequest is what the test webhook receiver captured.
type receivedRequest struct {
	headers http.Header
	body    []byte
}

// webhookReceiver is a test HTTPS receiver that records requests and can be
// told what status to return.
type webhookReceiver struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []receivedRequest
	status   int
	response string
}

func newWebhookReceiver(t *testing.T) *webhookReceiver {
	t.Helper()

	r := &webhookReceiver{status: http.StatusOK}
	r.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)

		r.mu.Lock()
		r.requests = append(r.requests, receivedRequest{headers: req.Header.Clone(), body: body})
		status, response := r.status, r.response
		r.mu.Unlock()

		w.WriteHeader(status)
		if response != "" {
			_, _ = w.Write([]byte(response))
		}
	}))
	t.Cleanup(r.server.Close)

	return r
}

func (r *webhookReceiver) received() []receivedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]receivedRequest(nil), r.requests...)
}

func (r *webhookReceiver) respondWith(status int, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.status, r.response = status, body
}

// newWebhookFor builds a webhook notifier pointed at the test receiver, using
// the receiver's own TLS client so the self-signed certificate is trusted.
func newWebhookFor(t *testing.T, r *webhookReceiver, sec *secret.Secret) notify.Notifier {
	t.Helper()

	notifier, err := notify.New(notify.Config{
		Name:     "ops-hook",
		Kind:     notify.KindWebhook,
		Settings: map[string]string{notify.SettingURL: r.server.URL + "/hook", notify.SettingTimeout: "10s"},
	}, sec)
	require.NoError(t, err)

	// httptest's TLS server uses a self-signed certificate. Swapping the
	// transport is confined to the test; the notifier itself has no option to
	// skip verification, which is deliberate.
	notify.SetHTTPClientForTest(notifier, r.server.Client())

	return notifier
}

func TestWebhookDeliversSignedJSON(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	sec := testSecret(t)

	receiver := newWebhookReceiver(t)
	notifier := newWebhookFor(t, receiver, sec)

	e := event.New(event.Type("host.updated"), "example.org", "address changed").
		WithField("ip", "203.0.113.1")

	require.NoError(t, notifier.Deliver(ctx, e))

	requests := receiver.received()
	require.Len(t, requests, 1)
	got := requests[0]

	// The payload.
	var payload struct {
		ID         string            `json:"id"`
		Type       string            `json:"type"`
		OccurredAt time.Time         `json:"occurred_at"`
		Subject    string            `json:"subject"`
		Message    string            `json:"message"`
		Fields     map[string]string `json:"fields"`
	}
	require.NoError(t, json.Unmarshal(got.body, &payload))
	asrt.Equal(e.ID, payload.ID)
	asrt.Equal("host.updated", payload.Type)
	asrt.Equal("example.org", payload.Subject)
	asrt.Equal("address changed", payload.Message)
	asrt.Equal("203.0.113.1", payload.Fields["ip"])

	// Routing headers, so a receiver need not parse the body to dispatch.
	asrt.Equal("host.updated", got.headers.Get(notify.HeaderEvent))
	asrt.Equal(e.ID, got.headers.Get(notify.HeaderEventID))
	asrt.Equal("application/json", got.headers.Get("Content-Type"))

	// The signature verifies against the key derived from the same secret.
	key, err := sec.DeriveHMACKey("netory/webhook-signing")
	require.NoError(t, err)

	timestamp := got.headers.Get(notify.HeaderTimestamp)
	asrt.NotEmpty(timestamp)
	asrt.True(notify.Verify(key, timestamp, got.body, got.headers.Get(notify.HeaderSignature)),
		"the receiver must be able to verify the signature")
}

// The signature must actually detect tampering, and must cover the timestamp so
// a captured request cannot be replayed forever.
func TestWebhookSignatureDetectsTampering(t *testing.T) {
	asrt := assert.New(t)
	sec := testSecret(t)

	key, err := sec.DeriveHMACKey("netory/webhook-signing")
	require.NoError(t, err)

	body := []byte(`{"id":"abc","type":"host.updated"}`)
	timestamp := "1760000000"
	signature := notify.Sign(key, timestamp, body)

	asrt.True(notify.Verify(key, timestamp, body, signature))

	// A modified body fails.
	asrt.False(notify.Verify(key, timestamp, []byte(`{"id":"abc","type":"host.deleted"}`), signature))

	// A modified timestamp fails, which is what makes replay detectable.
	asrt.False(notify.Verify(key, "1760000001", body, signature))

	// A different key fails, so one service's signature is not valid at
	// another's receiver.
	otherSec := testSecret(t)
	otherKey, err := otherSec.DeriveHMACKey("netory/webhook-signing")
	require.NoError(t, err)
	asrt.False(notify.Verify(otherKey, timestamp, body, signature))

	// And a key derived for a different purpose fails, which is the HKDF
	// separation doing its job.
	cacheKey, err := sec.DeriveHMACKey("netory/some-other-purpose")
	require.NoError(t, err)
	asrt.False(notify.Verify(cacheKey, timestamp, body, signature))

	asrt.False(notify.Verify(key, timestamp, body, "sha256=00"))
	asrt.False(notify.Verify(key, timestamp, body, ""))
}

func TestWebhookReportsANonSuccessStatus(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	receiver := newWebhookReceiver(t)
	notifier := newWebhookFor(t, receiver, testSecret(t))

	receiver.respondWith(http.StatusServiceUnavailable, "backend is down")

	err := notifier.Deliver(ctx, event.New(event.Type("host.updated"), "example.org", ""))
	asrt.Error(err)
	asrt.Contains(err.Error(), "503")
	asrt.Contains(err.Error(), "backend is down")

	// The URL in the error is redacted: the error text reaches the log and the
	// outbox's LastError field.
	asrt.NotContains(err.Error(), "/hook")
	asrt.Contains(err.Error(), "(redacted)")
}

// An error body must not be able to fill the outbox entry with megabytes of
// HTML.
func TestWebhookTruncatesAHugeErrorBody(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	receiver := newWebhookReceiver(t)
	notifier := newWebhookFor(t, receiver, testSecret(t))

	receiver.respondWith(http.StatusInternalServerError, strings.Repeat("x", 1<<20))

	err := notifier.Deliver(ctx, event.New(event.Type("host.updated"), "example.org", ""))
	asrt.Error(err)
	asrt.Less(len(err.Error()), 16<<10, "the error message must be bounded, got %d bytes", len(err.Error()))
}

// Event data reaching a header must not be able to break the request. Go's
// http client rejects a header containing a newline outright, which would turn
// a hostile hostname into a delivery that fails forever.
func TestWebhookSanitisesHeadersBuiltFromEventData(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	receiver := newWebhookReceiver(t)
	notifier := newWebhookFor(t, receiver, testSecret(t))

	hostile := event.Event{
		ID:         "abc\r\nX-Injected: yes",
		Type:       event.Type("auth.failed\r\nX-Also-Injected: yes"),
		OccurredAt: time.Now().UTC(),
		Subject:    "evil.example",
	}

	asrt.NoError(notifier.Deliver(ctx, hostile), "a hostile header value must not fail the delivery")

	requests := receiver.received()
	require.Len(t, requests, 1)

	asrt.Empty(requests[0].headers.Get("X-Injected"))
	asrt.Empty(requests[0].headers.Get("X-Also-Injected"))
	asrt.NotContains(requests[0].headers.Get(notify.HeaderEventID), "\r")
	asrt.NotContains(requests[0].headers.Get(notify.HeaderEvent), "\n")
}
