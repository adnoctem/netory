package notify

import (
	"net/http"

	"github.com/adnoctem/netory/pkg/event"
)

// This file is compiled only into the test binary, so these hooks reach the
// package's internals without widening its shipped API. The alternative -
// exporting them for real - would put a "replace the HTTP client" and a
// "render a message without sending it" entry point into the production
// surface for no caller's benefit.

// SetHTTPClientForTest replaces a webhook notifier's HTTP client, so tests can
// point one at an httptest TLS server whose certificate is self-signed.
//
// There is deliberately no configuration option for this. A notifier with a
// "skip TLS verification" setting is a notifier that will eventually be
// deployed with it set.
func SetHTTPClientForTest(n Notifier, c *http.Client) {
	if w, ok := n.(*webhookNotifier); ok {
		w.client = c
	}
}

// ComposeForTest renders an event as a mail message without sending it, so the
// header-injection defence can be asserted on the actual bytes.
func ComposeForTest(n Notifier, e event.Event) ([]byte, error) {
	s, ok := n.(*smtpNotifier)
	if !ok {
		return nil, nil
	}

	return s.compose(e)
}

// SanitizeHeaderForTest exposes the header sanitiser directly.
func SanitizeHeaderForTest(value string) string { return sanitizeHeader(value) }

// EncodeSubjectForTest exposes the subject encoder directly.
func EncodeSubjectForTest(subject string) string { return encodeSubject(subject) }
