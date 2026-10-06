// Package admin is the Unix-domain-socket plumbing shared by protean, signpost
// and pivot.
//
// All three expose their administrative surface on a Unix socket rather than a
// network API, and none of them has a remote admin API at all. Authorization
// is the socket's file permissions: the socket is created 0600 and owned by the
// service user, so reaching it already requires being that user or root. There
// are no tokens to issue, rotate or leak, because there is nothing listening
// remotely to present one to.
//
// # Why net/http over the socket
//
// The transport is ordinary HTTP/1.1 spoken over AF_UNIX. A hand-rolled framing
// protocol would mean reimplementing request routing, method semantics, status
// codes, timeouts and context cancellation, all of which net/http already has
// and none of which is interesting work. The socket is the security boundary;
// the protocol on top of it is a detail, so it should be the boring one.
//
// The HTTP host is meaningless here - there is no DNS name behind a socket - so
// clients address requests to http://admin and the server ignores it.
//
// # Identity for the audit log
//
// All three services must record who performed an administrative action
// (protean section 9.2, signpost section 8.1, pivot section 9.2). Over a Unix
// socket the kernel will answer that question directly, via SO_PEERCRED, so
// Peer carries the connecting process's real uid, gid and pid. That is an
// identity the caller cannot assert for itself, which is what makes it worth
// writing down - a self-declared "user" field in a request body would be
// decoration.
package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// DefaultSocketMode is the permission the socket is created with. It is the
// whole authorization model, so it is not configurable.
const DefaultSocketMode = 0o600

// MaxRequestBytes bounds an admin request body. The socket is reachable only by
// the service user, so this guards against a runaway client rather than an
// attacker - but an unbounded json.Decoder on a long-lived server is a memory
// bug waiting for a malformed request.
const MaxRequestBytes = 8 << 20 // 8 MiB

// Error is a structured administrative error.
//
// Hint is separate from Message because the two are for different moments: the
// message says what went wrong, the hint says what to do about it. All three
// design documents require user-facing messages to carry a hint, and keeping
// them apart means the CLI can render the hint on its own line while errors.Is
// and %w keep working against the message.
type Error struct {
	// Status is the HTTP status the server used, zero on the server side
	// before it is written.
	Status int `json:"-"`

	// Message is what went wrong.
	Message string `json:"error"`

	// Hint is what the operator should do about it. It may be empty.
	Hint string `json:"hint,omitempty"`
}

// Error implements error. It deliberately returns the message alone: a wrapped
// chain reads better without every layer repeating its own advice, and the hint
// is retrieved with HintFor when it is time to show it to someone.
func (e *Error) Error() string { return e.Message }

// Errorf builds an Error with no hint.
func Errorf(status int, format string, args ...any) *Error {
	return &Error{Status: status, Message: fmt.Sprintf(format, args...)}
}

// WithHint returns a copy of e carrying the given hint.
func (e *Error) WithHint(format string, args ...any) *Error {
	out := *e
	out.Hint = fmt.Sprintf(format, args...)

	return &out
}

// HintFor walks err's chain and returns the first hint it finds, or "".
func HintFor(err error) string {
	var adminErr *Error
	for err != nil {
		if errors.As(err, &adminErr) && adminErr.Hint != "" {
			return adminErr.Hint
		}

		err = errors.Unwrap(err)
	}

	return ""
}

// WriteJSON writes v as JSON with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if v == nil {
		return
	}

	// The status line is already sent, so a failure here cannot be reported to
	// the client. It is left to the caller's audit log, which records the
	// status that was written.
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes err as a JSON error response. An *Error contributes its own
// status and hint; any other error becomes a 500 with no hint, so an internal
// failure cannot leak its text as operator advice.
func WriteError(w http.ResponseWriter, err error) {
	var adminErr *Error
	if !errors.As(err, &adminErr) {
		adminErr = &Error{Status: http.StatusInternalServerError, Message: err.Error()}
	}

	status := adminErr.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}

	WriteJSON(w, status, &Error{Message: adminErr.Message, Hint: adminErr.Hint})
}

// DecodeJSON reads a JSON request body into v, with the body size bounded and
// unknown fields rejected.
//
// Rejecting unknown fields turns a typo in an administrative request into an
// error instead of a silently ignored field - `--privder cloudflare` should
// fail loudly, not create a host with no provider.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		return Errorf(http.StatusBadRequest, "malformed request body: %v", err).
			WithHint("this is a bug in the CLI rather than something you can fix in the request")
	}

	// A second value in the stream means the caller sent two JSON documents,
	// which no handler expects.
	if dec.More() {
		return Errorf(http.StatusBadRequest, "request body contains more than one JSON document").
			WithHint("this is a bug in the CLI rather than something you can fix in the request")
	}

	return nil
}

// socketInUse reports whether the error from a probe dial means another server
// already holds the socket, as opposed to the socket being a stale file.
func socketInUse(dialErr error) bool { return dialErr == nil }

// trimPath normalises a request path for the audit log, so a logged path cannot
// smuggle a newline into the record.
func trimPath(p string) string {
	p = strings.ReplaceAll(p, "\n", "")
	p = strings.ReplaceAll(p, "\r", "")

	return p
}
