package forwarded_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/forwarded"
)

// trusted is the proxy network these tests declare.
var trusted = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// request builds a plain-HTTP request from a peer, with optional headers.
func request(peer string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = peer

	for name, value := range headers {
		req.Header.Set(name, value)
	}

	return req
}

func TestPeer(t *testing.T) {
	t.Parallel()

	asrt := assert.New(t)

	for input, want := range map[string]string{
		"203.0.113.7:54321":   "203.0.113.7",
		"[2001:db8::1]:443":   "2001:db8::1",
		"203.0.113.7":         "203.0.113.7",
		"[::ffff:10.0.0.1]:1": "10.0.0.1",
	} {
		addr, err := forwarded.Peer(request(input, nil))
		require.NoError(t, err, input)
		asrt.Equal(want, addr.String(), input)
	}

	_, err := forwarded.Peer(request("not-an-address", nil))
	assert.ErrorIs(t, err, forwarded.ErrNoSourceAddress)
}

// The classic mistake this package exists to avoid: taking the leftmost
// X-Forwarded-For entry. The left of that list is whatever the client sent, so
// a client can prepend any address it likes.
func TestSourceWalksForwardedForFromTheRight(t *testing.T) {
	t.Parallel()

	resolver := forwarded.NewResolver(trusted)

	addr, err := resolver.Source(request("192.0.2.1:443", map[string]string{
		forwarded.HeaderFor: "198.51.100.9, 203.0.113.7",
	}))
	require.NoError(t, err)

	assert.Equal(t, "203.0.113.7", addr.String(),
		"the rightmost untrusted entry is the client; the left of the list is attacker-controlled")
}

func TestSourceSkipsChainedProxies(t *testing.T) {
	t.Parallel()

	resolver := forwarded.NewResolver(trusted)

	addr, err := resolver.Source(request("192.0.2.1:443", map[string]string{
		forwarded.HeaderFor: "203.0.113.7, 192.0.2.5, 192.0.2.6",
	}))
	require.NoError(t, err)

	assert.Equal(t, "203.0.113.7", addr.String())
}

func TestSourceIgnoresHeadersFromAnUntrustedPeer(t *testing.T) {
	t.Parallel()

	resolver := forwarded.NewResolver(trusted)

	addr, err := resolver.Source(request("198.51.100.9:443", map[string]string{
		forwarded.HeaderFor: "203.0.113.7",
	}))
	require.NoError(t, err)

	assert.Equal(t, "198.51.100.9", addr.String(),
		"a peer that is not a declared proxy is the client, whatever headers it sent")
}

// An unparsable entry stops the walk rather than being skipped: continuing
// would mean trusting entries further left, which sit behind a hop this code
// cannot account for.
func TestSourceStopsAtAnUnparsableEntry(t *testing.T) {
	t.Parallel()

	resolver := forwarded.NewResolver(trusted)

	addr, err := resolver.Source(request("192.0.2.1:443", map[string]string{
		forwarded.HeaderFor: "203.0.113.7, garbage, 192.0.2.5",
	}))
	require.NoError(t, err)

	assert.Equal(t, "192.0.2.1", addr.String(),
		"the walk stops at the malformed entry and falls back to the peer")
}

func TestSourceWithEveryEntryTrusted(t *testing.T) {
	t.Parallel()

	resolver := forwarded.NewResolver(trusted)

	addr, err := resolver.Source(request("192.0.2.1:443", map[string]string{
		forwarded.HeaderFor: "192.0.2.5, 192.0.2.6",
	}))
	require.NoError(t, err)

	assert.Equal(t, "192.0.2.1", addr.String())
}

func TestIsTrustedUnmapsIPv4(t *testing.T) {
	t.Parallel()

	resolver := forwarded.NewResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})

	assert.True(t, resolver.IsTrusted(netip.MustParseAddr("::ffff:10.0.0.1")),
		"a proxy configured as 10.0.0.0/8 must match a connection Go reports as ::ffff:10.0.0.1")
	assert.False(t, resolver.IsTrusted(netip.Addr{}))
}

func TestEncryption(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		trusted []netip.Prefix
		peer    string
		headers map[string]string
		native  bool
		want    forwarded.State
	}{
		{
			name:   "native TLS",
			peer:   "203.0.113.7:443",
			native: true,
			want:   forwarded.Encrypted,
		},
		{
			name:    "trusted proxy saying https",
			trusted: trusted,
			peer:    "192.0.2.1:80",
			headers: map[string]string{forwarded.HeaderProto: "https"},
			want:    forwarded.Encrypted,
		},
		{
			name:    "trusted proxy saying HTTPS in capitals",
			trusted: trusted,
			peer:    "192.0.2.1:80",
			headers: map[string]string{forwarded.HeaderProto: "HTTPS"},
			want:    forwarded.Encrypted,
		},
		{
			name:    "trusted proxy chain, leftmost wins",
			trusted: trusted,
			peer:    "192.0.2.1:80",
			headers: map[string]string{forwarded.HeaderProto: "https, http"},
			want:    forwarded.Encrypted,
		},
		{
			name:    "trusted proxy saying http",
			trusted: trusted,
			peer:    "192.0.2.1:80",
			headers: map[string]string{forwarded.HeaderProto: "http"},
			want:    forwarded.Plaintext,
		},
		{
			name:    "trusted proxy sending nothing",
			trusted: trusted,
			peer:    "192.0.2.1:80",
			want:    forwarded.Unknown,
		},
		{
			name:    "direct plaintext with a trusted set declared",
			trusted: trusted,
			peer:    "203.0.113.7:80",
			want:    forwarded.Plaintext,
		},
		{
			name: "plaintext with no trusted set declared",
			peer: "203.0.113.7:80",
			want: forwarded.Unknown,
		},
		{
			// An undeclared peer's header is not evidence of anything.
			name:    "untrusted peer claiming https",
			trusted: trusted,
			peer:    "203.0.113.7:80",
			headers: map[string]string{forwarded.HeaderProto: "https"},
			want:    forwarded.Plaintext,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			req := request(test.peer, test.headers)
			if test.native {
				req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
			}

			resolver := forwarded.NewResolver(test.trusted)
			assert.Equal(t, test.want, resolver.Encryption(req))
		})
	}
}

func TestStateString(t *testing.T) {
	t.Parallel()

	asrt := assert.New(t)
	asrt.Equal("encrypted", forwarded.Encrypted.String())
	asrt.Equal("plaintext", forwarded.Plaintext.String())
	asrt.Equal("unknown", forwarded.Unknown.String())
}

func TestEnforced(t *testing.T) {
	t.Parallel()

	assert.False(t, forwarded.NewResolver(nil).Enforced())
	assert.True(t, forwarded.NewResolver(trusted).Enforced())
}
