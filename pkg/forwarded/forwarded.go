// Package forwarded works out where an HTTP request came from and whether it
// arrived over TLS.
//
// It exists once, shared by every netory service, because it is the wrong
// thing to have two of. Reading X-Forwarded-For correctly is a small piece of
// code with a well-known way of being wrong, and the consequences differ per
// service but are serious in all of them: protean writes the resolved address
// into DNS and rate-limits on it, and signpost refuses to serve a script
// unless it can confirm the hop was encrypted. A second copy that drifted
// would break one of those silently.
//
// Nothing here is consulted unless the TCP peer is a declared trusted proxy.
// Headers from anything else are what the client chose to send.
package forwarded

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// The forwarding headers this package reads.
const (
	HeaderFor   = "X-Forwarded-For"
	HeaderProto = "X-Forwarded-Proto"
)

// ErrNoSourceAddress is returned when a request's source cannot be determined
// at all, which should not happen over TCP.
var ErrNoSourceAddress = errors.New("forwarded: could not determine the request's source address")

// Resolver answers both questions for one configured trusted set.
type Resolver struct {
	trusted []netip.Prefix

	// enforced reports whether the operator declared a trusted set at all.
	//
	// It is the difference between "this request did not come over TLS" and
	// "I cannot tell". With no trusted set declared, a service behind a proxy
	// and a service exposed directly are indistinguishable from inside the
	// process, so the honest answer is Unknown and the caller decides.
	enforced bool
}

// NewResolver builds a resolver over a trusted-proxy set.
func NewResolver(trusted []netip.Prefix) *Resolver {
	return &Resolver{
		trusted:  trusted,
		enforced: len(trusted) > 0,
	}
}

// Enforced reports whether a trusted-proxy set was declared.
func (r *Resolver) Enforced() bool { return r.enforced }

// IsTrusted reports whether addr is a declared proxy.
//
// The address is unmapped first, or a proxy configured as 10.0.0.0/8 would
// not match a connection Go reports as ::ffff:10.0.0.1.
func (r *Resolver) IsTrusted(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	addr = addr.Unmap()

	for _, prefix := range r.trusted {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

// Peer returns the address of the TCP peer, which is the proxy in proxy mode
// and the client otherwise.
func Peer(req *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// A RemoteAddr without a port happens in tests and with some
		// listeners; try it whole before giving up.
		if addr, parseErr := netip.ParseAddr(req.RemoteAddr); parseErr == nil {
			return addr.Unmap(), nil
		}

		return netip.Addr{}, ErrNoSourceAddress
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, ErrNoSourceAddress
	}

	return addr.Unmap(), nil
}

// Source returns the client's address for a request.
//
// In proxy mode with a trusted peer, X-Forwarded-For is walked from the right,
// skipping entries that are themselves trusted proxies, and the first
// untrusted entry is the client. Taking the leftmost entry instead - the
// obvious reading of "the client is first" - is the classic mistake: the left
// of that list is whatever the client sent, so a client can prepend any
// address it likes.
func (r *Resolver) Source(req *http.Request) (netip.Addr, error) {
	peer, err := Peer(req)
	if err != nil {
		return netip.Addr{}, err
	}

	// A peer that is not a declared proxy is the client itself, whatever
	// headers it sent.
	if !r.IsTrusted(peer) {
		return peer, nil
	}

	header := req.Header.Get(HeaderFor)
	if header == "" {
		return peer, nil
	}

	entries := strings.Split(header, ",")
	for i := len(entries) - 1; i >= 0; i-- {
		candidate, ok := parseEntry(entries[i])
		if !ok {
			// An unparsable entry ends the walk. Continuing past it would
			// mean trusting entries further left, which sit behind a hop this
			// code cannot account for.
			break
		}

		if !r.IsTrusted(candidate) {
			return candidate, nil
		}
	}

	// Every entry was a trusted proxy, so the peer is the best answer
	// available.
	return peer, nil
}

// parseEntry parses one X-Forwarded-For entry.
//
// It reports ok rather than an error because a malformed entry is not a
// failure to propagate - the walk simply stops there and falls back to the
// peer, which is the conservative answer.
func parseEntry(entry string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(entry))
	if err != nil {
		return netip.Addr{}, false
	}

	return addr.Unmap(), true
}

// State describes how a request reached the service.
type State int

// The three answers this package can give about a request's transport.
const (
	// Encrypted means the request arrived over TLS, either directly or via a
	// trusted proxy that said so.
	Encrypted State = iota

	// Plaintext means the request demonstrably did not arrive over TLS.
	Plaintext

	// Unknown means it cannot be told: proxy mode with no trusted set
	// declared, or a trusted proxy that sends no X-Forwarded-Proto.
	Unknown
)

// String renders the state for a log line.
func (s State) String() string {
	switch s {
	case Encrypted:
		return "encrypted"
	case Plaintext:
		return "plaintext"
	case Unknown:
		return "unknown"
	default:
		return "invalid"
	}
}

// Encryption reports whether a request arrived over TLS.
func (r *Resolver) Encryption(req *http.Request) State {
	// Native TLS: the connection itself is the evidence.
	if req.TLS != nil {
		return Encrypted
	}

	peer, err := Peer(req)
	if err != nil {
		return Unknown
	}

	// Plain HTTP from something that is not a declared proxy. If a trusted set
	// was declared, this request bypassed the proxy and arrived in the clear.
	if !r.IsTrusted(peer) {
		if r.enforced {
			return Plaintext
		}

		return Unknown
	}

	switch strings.ToLower(strings.TrimSpace(firstProto(req))) {
	case "https":
		return Encrypted
	case "":
		// A trusted proxy that does not set the header. It cannot be told, and
		// refusing would break a working deployment over a header the operator
		// may not control. The caller decides what Unknown costs it.
		return Unknown
	default:
		return Plaintext
	}
}

// firstProto returns the leftmost X-Forwarded-Proto value.
//
// The leftmost is correct here, unlike X-Forwarded-For: this header records
// the scheme of the original client connection, and each proxy prepends. The
// value is only consulted at all when the peer is a trusted proxy.
func firstProto(req *http.Request) string {
	raw := req.Header.Get(HeaderProto)
	if raw == "" {
		return ""
	}

	if first, _, found := strings.Cut(raw, ","); found {
		return first
	}

	return raw
}
