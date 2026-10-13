package server

import (
	"net/http"
	"strings"
)

// Response is a DynDNS2 return code.
//
// The protocol answers with a short plain-text token, optionally followed by
// the address. Every relevant client - ddclient, inadyn, a FRITZ!Box custom
// provider - already parses these, which is the whole reason protean speaks
// DynDNS2 rather than something nicer: a better protocol that needs new router
// firmware is worse than an old protocol that works today.
type Response string

// The DynDNS2 return codes protean uses.
const (
	// RespGood means the address was updated. It is followed by the address.
	RespGood Response = "good"

	// RespNoChange means the address was already correct. Also followed by the
	// address. This is the common case for a client that re-sends every five
	// minutes, and it costs no provider call.
	RespNoChange Response = "nochg"

	// RespBadAuth means the credentials were rejected.
	RespBadAuth Response = "badauth"

	// RespNoHost means the hostname is not configured for this account.
	RespNoHost Response = "nohost"

	// RespNotFQDN means the hostname was not fully qualified.
	RespNotFQDN Response = "notfqdn"

	// RespAbuse means the client is being rate limited.
	RespAbuse Response = "abuse"

	// RespDNSErr means the DNS provider rejected or failed the update.
	RespDNSErr Response = "dnserr"

	// RespServerError is DynDNS2's generic server failure.
	RespServerError Response = "911"
)

// String renders the response token.
func (r Response) String() string { return string(r) }

// httpStatus maps a DynDNS2 code onto an HTTP status.
//
// DynDNS2 itself answers 200 for everything and puts the outcome in the body,
// which is what the clients read. protean returns a matching HTTP status
// anyway, because an operator watching a reverse proxy's access log should be
// able to see failures without parsing bodies - and because a 200 for "badauth"
// makes every monitoring tool report the service as healthy while it rejects
// every update.
//
// Clients are unaffected: they read the body.
func (r Response) httpStatus() int {
	switch r {
	case RespGood, RespNoChange:
		return http.StatusOK
	case RespBadAuth:
		return http.StatusUnauthorized
	case RespNoHost, RespNotFQDN:
		return http.StatusBadRequest
	case RespAbuse:
		return http.StatusTooManyRequests
	case RespDNSErr:
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

// write sends a DynDNS2 response.
//
// The body is the token, a space and the address when there is one, which is
// the format the protocol specifies and clients match against.
func (r Response) write(w http.ResponseWriter, addresses ...string) {
	var b strings.Builder
	b.WriteString(string(r))

	for _, addr := range addresses {
		if addr == "" {
			continue
		}

		b.WriteString(" ")
		b.WriteString(addr)
	}

	body := b.String()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// Nothing about an update response is cacheable, and a cached "nochg"
	// would be actively wrong.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(r.httpStatus())

	_, _ = w.Write([]byte(body + "\n"))
}
