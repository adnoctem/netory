package server

import (
	"net/http"
	"net/netip"

	"github.com/adnoctem/netory/internal/protean/config"
	"github.com/adnoctem/netory/pkg/forwarded"
)

// Forwarding headers protean consults, and only from a trusted peer.
const (
	HeaderForwardedFor   = forwarded.HeaderFor
	HeaderForwardedProto = forwarded.HeaderProto
)

// SourceResolver works out which address a request came from.
//
// This is not a convenience: the address it returns feeds the per-source rate
// limiter, the auth.failed event, and - when a client sends no explicit myip -
// the address written into DNS. Getting it wrong means a client can choose its
// own apparent address and walk past the rate limiter, or that every client
// appears to be the reverse proxy.
//
// The parsing itself lives in pkg/forwarded, shared with signpost and pivot.
// One implementation rather than three, because this is exactly the kind of
// code where a second copy drifts and the drift is invisible until someone
// spoofs an address.
type SourceResolver struct {
	resolver *forwarded.Resolver
	cfg      config.Config
}

// NewSourceResolver builds a resolver from the bootstrap configuration.
func NewSourceResolver(cfg config.Config) *SourceResolver {
	return &SourceResolver{
		// Enforcement is on only when the operator actually declared a trusted
		// set. With none declared, protean cannot tell a proxied request from a
		// direct one, so it does not pretend to - it warns at startup instead.
		// See state.LogStartup.
		resolver: forwarded.NewResolver(cfg.TrustedProxies),
		cfg:      cfg,
	}
}

// Peer returns the address of the TCP peer, which is the proxy in proxy mode
// and the client otherwise.
func Peer(r *http.Request) (netip.Addr, error) { return forwarded.Peer(r) }

// Source returns the client's address for a request.
func (s *SourceResolver) Source(r *http.Request) (netip.Addr, error) {
	return s.resolver.Source(r)
}

// EncryptionState describes how a request reached protean.
type EncryptionState = forwarded.State

// The three answers protean can give about a request's transport.
const (
	// Encrypted means the request arrived over TLS, either directly or via a
	// trusted proxy that said so.
	Encrypted = forwarded.Encrypted

	// Plaintext means the request demonstrably did not arrive over TLS.
	Plaintext = forwarded.Plaintext

	// Unknown means protean cannot tell: proxy mode with no trusted set
	// declared, or a trusted proxy that sends no X-Forwarded-Proto.
	Unknown = forwarded.Unknown
)

// Encryption reports whether a request arrived over TLS.
//
// This matters because the DynDNS2 endpoint authenticates with HTTP Basic,
// which sends the token on every single request. A token on a
// plaintext hop is a disclosed token, and the client will keep sending it every
// five minutes.
func (s *SourceResolver) Encryption(r *http.Request) EncryptionState {
	return s.resolver.Encryption(r)
}
