package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/secret"
)

// KindWebhook is the registered kind for the HTTP webhook transport.
const KindWebhook = "webhook"

// Webhook setting keys.
const (
	SettingURL     = "url"
	SettingTimeout = "timeout"
)

// Webhook signature headers.
const (
	// HeaderSignature carries the hex-encoded HMAC-SHA256 of the body,
	// prefixed with the algorithm so a future change is distinguishable rather
	// than silently reinterpreted.
	HeaderSignature = "X-Netory-Signature"

	// HeaderTimestamp carries the Unix seconds the request was signed at, and
	// is itself covered by the signature.
	HeaderTimestamp = "X-Netory-Timestamp"

	// HeaderEvent and HeaderEventID let a receiver route and deduplicate
	// without parsing the body.
	HeaderEvent   = "X-Netory-Event"
	HeaderEventID = "X-Netory-Event-ID"
)

// signaturePrefix names the algorithm in the signature header value.
const signaturePrefix = "sha256="

// DefaultWebhookTimeout bounds one delivery attempt.
const DefaultWebhookTimeout = 30 * time.Second

// maxWebhookResponseBytes bounds how much of a receiver's response is read for
// the error message. A receiver returning megabytes of HTML on an error should
// not be able to put it all in the outbox's LastError field.
const maxWebhookResponseBytes = 4 << 10

// webhookSigningInfo is the HKDF label for the signing key. It is
// service-agnostic on purpose: the derivation already separates services,
// because each one's secret is different.
const webhookSigningInfo = "netory/webhook-signing"

func init() {
	// The URL is declared secret: a webhook endpoint frequently carries a
	// token in its path or query, so `notifier list` must not print it.
	Register(KindWebhook, newWebhook, SettingURL)
}

// webhookNotifier posts events as signed JSON.
type webhookNotifier struct {
	name   string
	url    string
	key    []byte
	client *http.Client
}

// newWebhook builds a webhook notifier, deriving its signing key from the
// service secret.
func newWebhook(cfg Config, sec *secret.Secret) (Notifier, error) {
	raw, err := cfg.require(SettingURL)
	if err != nil {
		return nil, err
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("setting %q is not a valid URL: %w", SettingURL, err)
	}

	// https only. The body is signed, so a receiver can detect tampering - but
	// the signature says nothing about confidentiality, and an event body
	// carries hostnames, IP addresses and failure reasons.
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf(
			"setting %q must be an https URL, got scheme %q: event payloads carry personal data such as IP addresses",
			SettingURL, parsed.Scheme,
		)
	}

	if parsed.Host == "" {
		return nil, fmt.Errorf("setting %q has no host", SettingURL)
	}

	if sec == nil {
		return nil, errors.New("a service secret is required to derive the webhook signing key")
	}

	key, err := sec.DeriveHMACKey(webhookSigningInfo)
	if err != nil {
		return nil, fmt.Errorf("derive the webhook signing key: %w", err)
	}

	timeout := DefaultWebhookTimeout
	if rawTimeout := cfg.Setting(SettingTimeout); rawTimeout != "" {
		parsedTimeout, err := time.ParseDuration(rawTimeout)
		if err != nil || parsedTimeout <= 0 {
			return nil, fmt.Errorf("setting %q must be a positive duration, got %q", SettingTimeout, rawTimeout)
		}

		timeout = parsedTimeout
	}

	return &webhookNotifier{
		name:   cfg.Name,
		url:    raw,
		key:    key,
		client: &http.Client{Timeout: timeout},
	}, nil
}

func (w *webhookNotifier) Name() string { return w.name }
func (w *webhookNotifier) Kind() string { return KindWebhook }

// Redacted implements Notifier. The URL is reported as its scheme and host
// only, so an operator can confirm which endpoint is configured without the
// path or query - which is where a token would be.
func (w *webhookNotifier) Redacted() map[string]string {
	out := map[string]string{SettingTimeout: w.client.Timeout.String()}

	if parsed, err := url.Parse(w.url); err == nil {
		out[SettingURL] = parsed.Scheme + "://" + parsed.Host
		if parsed.Path != "" && parsed.Path != "/" {
			out[SettingURL] += "/(redacted)"
		}
	} else {
		out[SettingURL] = "(set)"
	}

	return out
}

// webhookPayload is the JSON body posted to the receiver.
type webhookPayload struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	OccurredAt time.Time         `json:"occurred_at"`
	Subject    string            `json:"subject,omitempty"`
	Message    string            `json:"message,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
}

// Deliver posts one signed request.
func (w *webhookNotifier) Deliver(ctx context.Context, e event.Event) error {
	body, err := json.Marshal(webhookPayload{
		ID:         e.ID,
		Type:       string(e.Type),
		OccurredAt: e.OccurredAt,
		Subject:    e.Subject,
		Message:    e.Message,
		Fields:     e.Fields,
	})
	if err != nil {
		return fmt.Errorf("notify: webhook %q: encode payload: %w", w.name, err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: webhook %q: build request: %w", w.name, err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "netory")

	// Header values derived from event data are sanitised for the same reason
	// as in SMTP. Go's http client would reject a header containing a newline
	// outright, so this turns a rejected delivery that retries forever into a
	// delivered one with a harmless header.
	req.Header.Set(HeaderEvent, sanitizeHeader(string(e.Type)))
	req.Header.Set(HeaderEventID, sanitizeHeader(e.ID))
	req.Header.Set(HeaderTimestamp, timestamp)
	req.Header.Set(HeaderSignature, Sign(w.key, timestamp, body))

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: webhook %q: post to %s: %w", w.name, redactURL(w.url), err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, maxWebhookResponseBytes))

		message := fmt.Sprintf("notify: webhook %q: %s returned %s",
			w.name, redactURL(w.url), resp.Status)
		if trimmed := strings.TrimSpace(string(detail)); trimmed != "" {
			message += ": " + trimmed
		}

		return errors.New(message)
	}

	return nil
}

// Sign returns the signature for a webhook request.
//
// The timestamp is signed along with the body so a receiver can reject a
// replayed request by rejecting an old timestamp. Signing the body alone would
// make every captured request valid forever, since an event body is constant
// once emitted.
func Sign(key []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, key)

	// The timestamp and body are joined with a byte that cannot appear in the
	// decimal timestamp, so no (timestamp, body) pair can produce the same
	// input as a different pair.
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)

	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether a signature matches. Provided so a receiver written
// against this package - and the tests here - check signatures the same way the
// sender produces them.
//
// The comparison is constant-time. A byte-by-byte comparison would leak, via
// timing, how much of a forged signature was correct, which is enough to
// construct a valid one.
func Verify(key []byte, timestamp string, body []byte, signature string) bool {
	expected := Sign(key, timestamp, body)

	return hmac.Equal([]byte(expected), []byte(signature))
}

// redactURL reduces a URL to its scheme and host, for an error message. A
// webhook URL frequently carries a token in its path or query, and an error
// message ends up in the outbox and in the log.
func redactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "(redacted)"
	}

	out := parsed.Scheme + "://" + parsed.Host
	if parsed.Path != "" && parsed.Path != "/" {
		out += "/(redacted)"
	}

	return out
}
