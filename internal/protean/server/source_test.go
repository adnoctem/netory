package server_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/protean/config"
	"github.com/adnoctem/netory/internal/protean/server"
)

// resolverFor builds a resolver with the given trusted set.
func resolverFor(t *testing.T, trusted string) *server.SourceResolver {
	t.Helper()

	cfg := config.Default()

	prefixes, err := config.ParseTrustedProxies(trusted)
	require.NoError(t, err)
	cfg.TrustedProxies = prefixes

	return server.NewSourceResolver(cfg)
}

// request builds a request from a peer with an optional X-Forwarded-For.
func request(peer, forwardedFor string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/nic/update", nil)
	r.RemoteAddr = peer

	if forwardedFor != "" {
		r.Header.Set(server.HeaderForwardedFor, forwardedFor)
	}

	return r
}

// With no trusted proxies, the peer is the client whatever headers it sent.
// This is the load-bearing case: an unconfigured deployment must not let a
// client choose its own apparent address.
func TestSourceIgnoresHeadersFromAnUntrustedPeer(t *testing.T) {
	asrt := assert.New(t)
	resolver := resolverFor(t, "")

	addr, err := resolver.Source(request("203.0.113.5:40000", "198.51.100.9"))
	asrt.NoError(err)
	asrt.Equal("203.0.113.5", addr.String(),
		"a client must not be able to choose its own source address")
}

// A trusted proxy's X-Forwarded-For is honoured.
func TestSourceHonoursATrustedProxy(t *testing.T) {
	asrt := assert.New(t)
	resolver := resolverFor(t, "10.0.0.0/8")

	addr, err := resolver.Source(request("10.0.0.1:40000", "198.51.100.9"))
	asrt.NoError(err)
	asrt.Equal("198.51.100.9", addr.String())
}

// The walk is from the right, skipping trusted hops. Taking the leftmost entry
// - the obvious reading of "the client comes first" - is the classic mistake:
// the left of that list is whatever the client sent.
func TestSourceWalksForwardedForFromTheRight(t *testing.T) {
	asrt := assert.New(t)
	resolver := resolverFor(t, "10.0.0.0/8, 192.168.0.0/16")

	// A client that prepended a forged entry, behind two real proxies.
	addr, err := resolver.Source(request("10.0.0.1:40000",
		"1.2.3.4, 198.51.100.9, 192.168.1.1"))
	asrt.NoError(err)
	asrt.Equal("198.51.100.9", addr.String(),
		"the rightmost untrusted entry is the client; the forged one is further left and ignored")

	// A single forged entry from a client connecting through one proxy.
	addr, err = resolver.Source(request("10.0.0.1:40000", "1.2.3.4"))
	asrt.NoError(err)
	asrt.Equal("1.2.3.4", addr.String(),
		"with one hop the only entry is what the proxy recorded, which is the client")
}

// An unparsable entry ends the walk rather than being skipped past: entries
// further left sit behind a hop protean cannot account for.
func TestSourceStopsAtAnUnparsableEntry(t *testing.T) {
	asrt := assert.New(t)
	resolver := resolverFor(t, "10.0.0.0/8")

	addr, err := resolver.Source(request("10.0.0.1:40000", "198.51.100.9, garbage"))
	asrt.NoError(err)
	asrt.Equal("10.0.0.1", addr.String(), "the walk stops and falls back to the peer")
}

// Every entry being a trusted proxy leaves the peer as the best answer.
func TestSourceFallsBackWhenEveryHopIsTrusted(t *testing.T) {
	asrt := assert.New(t)
	resolver := resolverFor(t, "10.0.0.0/8")

	addr, err := resolver.Source(request("10.0.0.1:40000", "10.0.0.2, 10.0.0.3"))
	asrt.NoError(err)
	asrt.Equal("10.0.0.1", addr.String())
}

// A proxy configured as an IPv4 prefix must match a connection Go reports as
// an IPv4-mapped IPv6 address.
func TestSourceUnmapsIPv4MappedPeers(t *testing.T) {
	asrt := assert.New(t)
	resolver := resolverFor(t, "10.0.0.0/8")

	addr, err := resolver.Source(request("[::ffff:10.0.0.1]:40000", "198.51.100.9"))
	asrt.NoError(err)
	asrt.Equal("198.51.100.9", addr.String(),
		"an IPv4-mapped peer must still match an IPv4 trusted prefix")
}

// A bare address is accepted and widened to a single host, because
// "127.0.0.1" is what an operator will write.
func TestParseTrustedProxiesAcceptsBareAddresses(t *testing.T) {
	asrt := assert.New(t)

	prefixes, err := config.ParseTrustedProxies("127.0.0.1, 10.0.0.0/8, ::1")
	asrt.NoError(err)
	require.Len(t, prefixes, 3)

	asrt.Equal("127.0.0.1/32", prefixes[0].String())
	asrt.Equal("10.0.0.0/8", prefixes[1].String())
	asrt.Equal("::1/128", prefixes[2].String())

	// A host address inside a prefix is masked, so comparisons are consistent.
	prefixes, err = config.ParseTrustedProxies("10.1.2.3/8")
	asrt.NoError(err)
	asrt.Equal("10.0.0.0/8", prefixes[0].String())

	_, err = config.ParseTrustedProxies("not-an-address")
	asrt.Error(err)

	prefixes, err = config.ParseTrustedProxies("")
	asrt.NoError(err)
	asrt.Empty(prefixes)
}

// HTTP Basic sends the token on every request, so a plaintext hop is a
// disclosed token. The three answers protean can give are distinct for a
// reason: refusing on Unknown would break a working deployment over a header
// the operator may not control.
func TestEncryptionState(t *testing.T) {
	asrt := assert.New(t)

	tlsOn := tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}

	// Native TLS: the connection itself is the evidence.
	native := resolverFor(t, "")
	r := request("203.0.113.5:40000", "")
	r.TLS = &tlsOn
	asrt.Equal(server.Encrypted, native.Encryption(r))

	// Proxy mode, trusted peer, proxy says https.
	proxied := resolverFor(t, "10.0.0.0/8")
	r = request("10.0.0.1:40000", "")
	r.Header.Set(server.HeaderForwardedProto, "https")
	asrt.Equal(server.Encrypted, proxied.Encryption(r))

	// Trusted peer, proxy says http: the client's own hop was plaintext.
	r = request("10.0.0.1:40000", "")
	r.Header.Set(server.HeaderForwardedProto, "http")
	asrt.Equal(server.Plaintext, proxied.Encryption(r))

	// Several hops: the leftmost value is the original client's scheme, which
	// is the opposite of X-Forwarded-For's rightmost rule.
	r = request("10.0.0.1:40000", "")
	r.Header.Set(server.HeaderForwardedProto, "http, https")
	asrt.Equal(server.Plaintext, proxied.Encryption(r),
		"the leftmost X-Forwarded-Proto is the client's own hop")

	// Trusted peer, no header: protean cannot tell, and says so.
	r = request("10.0.0.1:40000", "")
	asrt.Equal(server.Unknown, proxied.Encryption(r))

	// A trusted set IS declared and this peer is not in it: the request
	// bypassed the proxy and arrived in the clear.
	r = request("203.0.113.5:40000", "")
	asrt.Equal(server.Plaintext, proxied.Encryption(r),
		"a direct plaintext connection past a declared proxy must be refused")

	// No trusted set declared: protean cannot distinguish, so it does not
	// pretend to. The startup warning covers this case.
	r = request("203.0.113.5:40000", "")
	asrt.Equal(server.Unknown, native.Encryption(r))
}

// A plaintext request must be refused by the update endpoint, not merely
// logged.
func TestUpdateRefusesPlaintext(t *testing.T) {
	asrt := assert.New(t)

	h := newHarness(t, func(cfg *config.Config) {
		prefixes, err := config.ParseTrustedProxies("10.0.0.0/8")
		require.NoError(t, err)
		cfg.TrustedProxies = prefixes
	})

	// A direct connection, past the declared proxy, with no TLS.
	req := httptest.NewRequest(http.MethodGet, server.UpdatePath+"?myip=203.0.113.1", nil)
	req.SetBasicAuth(h.host, h.token)
	req.RemoteAddr = "203.0.113.5:40000"

	rec := httptest.NewRecorder()
	h.update.ServeHTTP(rec, req)

	asrt.Equal(http.StatusUnauthorized, rec.Code)
	asrt.Equal("badauth", strings.TrimSpace(rec.Body.String()))
	asrt.Empty(h.fake.records(), "a token sent in the clear must not be acted on")
}
