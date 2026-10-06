package server_test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/protean/provider"
	"github.com/adnoctem/netory/internal/protean/server"
)

// These tests pin the three client shapes that exist in the wild. All three
// must work, because protean's whole reason for speaking DynDNS2 is that
// existing clients should need no changes.

// send issues a raw update request so a test can control the credentials and
// the query independently of the harness helper.
func (h *harness) send(t *testing.T, query, user, pass string) (int, string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, server.UpdatePath+query, nil)
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}

	rec := httptest.NewRecorder()
	h.update.ServeHTTP(rec, req)

	return rec.Code, strings.TrimSpace(rec.Body.String())
}

// Shape 1: ddclient and inadyn send the hostname as the Basic auth username,
// which is what DynDNS2 conventionally implies.
func TestClientShapeHostnameAsUsername(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	status, body := h.send(t, "?hostname=dyn.example.org&myip=203.0.113.1", h.host, h.token)
	asrt.Equal(http.StatusOK, status)
	asrt.Equal("good 203.0.113.1", body)
	asrt.Len(h.fake.records(), 1)
}

// Shape 2: a FRITZ!Box. It has separate Username, Password and "Domain name"
// fields and authenticates with HTTP Basic from the first two, so the username
// it sends is whatever the operator typed - an account name, not a hostname.
// The hostname arrives through the `hostname` parameter.
//
// Requiring username == hostname would mean typing the full hostname into a
// field labelled "Username", and otherwise getting badauth with no explanation.
func TestClientShapeFritzBoxArbitraryUsername(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	// A fresh address each time, since an unchanged one is answered `nochg`
	// without a provider call - which is correct, and would otherwise make
	// every iteration after the first look like a failure.
	for i, username := range []string{"fritzbox", "max", "protean-user", "7690"} {
		h.fake.reset()

		ipv4 := fmt.Sprintf("203.0.113.%d", i+1)
		ipv6 := fmt.Sprintf("2001:db8::%d", i+1)

		status, body := h.send(t,
			"?hostname=dyn.example.org&myip="+ipv4+"&myipv6="+ipv6, username, h.token)
		asrt.Equal(http.StatusOK, status, username)
		asrt.Equal("good "+ipv4+" "+ipv6, body, username)
		asrt.Len(h.fake.records(), 2, username)
	}
}

// Shape 3: no hostname asserted at all. The credential identifies the host at
// the provider's end, which is exactly how protean's tokens work - a token
// belongs to one host. The INWX FRITZ!Box guide recommends precisely this
// URL shape, with no <domain> placeholder in it.
func TestClientShapeNoHostnameAsserted(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	status, body := h.send(t, "?myip=203.0.113.1&myipv6=2001:db8::1", "anything", h.token)
	asrt.Equal(http.StatusOK, status)
	asrt.Contains(body, "good")

	records := h.fake.records()
	require.Len(t, records, 2)
	for _, record := range records {
		asrt.Equal("dyn", record.Name, "the host comes from the token, not from the request")
	}
}

// Loosening the username requirement must not loosen scoping. A valid token
// presented against a different hostname is still refused.
func TestTokenScopingSurvivesTheLooserUsername(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	// An explicit, well-formed hostname that is not this token's host.
	status, body := h.send(t, "?hostname=other.example.org&myip=203.0.113.1", "anything", h.token)
	asrt.Equal(http.StatusBadRequest, status)
	asrt.Equal("nohost", body, "a token may only ever update its own host")
	asrt.Empty(h.fake.records())

	// The same via the username, when the username *is* a well-formed
	// hostname - then it is read as a claim and checked.
	status, body = h.send(t, "?myip=203.0.113.1", "other.example.org", h.token)
	asrt.Equal(http.StatusBadRequest, status)
	asrt.Equal("nohost", body)
	asrt.Empty(h.fake.records())
}

// A username that does not look like a hostname is not a claim about which
// host to update, and must not be read as one. "fritzbox" is a username, not a
// bad hostname.
func TestNonHostnameUsernameIsNotAClaim(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	for i, username := range []string{"fritzbox", "max", "admin", "", "no-dots-here"} {
		h.fake.reset()

		// A changing address again, so each iteration is a real update rather
		// than a nochg.
		status, _ := h.send(t, fmt.Sprintf("?myip=203.0.113.%d", i+10), username, h.token)
		asrt.Equal(http.StatusOK, status, "username %q must not be mistaken for a hostname claim", username)
		asrt.Len(h.fake.records(), 1, "username %q", username)
	}
}

// A `hostname` parameter that is present but malformed is an error: the client
// meant to assert something and got it wrong.
func TestMalformedHostnameParameterIsNotFQDN(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	for _, bad := range []string{"localhost", "not..valid", "-leading.example.org", "203.0.113.1"} {
		status, body := h.send(t, "?hostname="+bad+"&myip=203.0.113.1", "fritzbox", h.token)
		asrt.Equal(http.StatusBadRequest, status, bad)
		asrt.Equal("notfqdn", body, bad)
	}

	asrt.Empty(h.fake.records())
}

// A wrong token is badauth whatever the username says, and reaches no provider.
func TestWrongTokenIsBadAuthRegardlessOfUsername(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	for _, username := range []string{h.host, "fritzbox", ""} {
		status, body := h.send(t, "?myip=203.0.113.1", username, "not-the-token")
		asrt.Equal(http.StatusUnauthorized, status, username)
		asrt.Equal("badauth", body, username)
	}

	asrt.Empty(h.fake.records())
}

// Credentials in the query string are refused, not accepted. A token in a URL
// appears in every access log and proxy log it passes through, which is the
// same exposure the plaintext refusal exists to prevent.
func TestQueryStringCredentialsAreRefused(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	for _, param := range []string{"password", "pass", "passwd", "pw", "token"} {
		status, body := h.send(t,
			"?hostname=dyn.example.org&myip=203.0.113.1&"+param+"="+h.token, "", "")
		asrt.Equal(http.StatusUnauthorized, status, param)
		asrt.Equal("badauth", body, param)
	}

	asrt.Empty(h.fake.records(), "a token sent in a URL must not be acted on")
}

// The realm is offered so a client - or an operator with curl - is told to
// retry with credentials rather than simply failing.
func TestMissingCredentialsOfferTheRealm(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	req := httptest.NewRequest(http.MethodGet, server.UpdatePath+"?myip=203.0.113.1", nil)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}

	rec := httptest.NewRecorder()
	h.update.ServeHTTP(rec, req)

	asrt.Equal(http.StatusUnauthorized, rec.Code)
	asrt.Contains(rec.Header().Get("WWW-Authenticate"), `realm="protean"`)
}

// POST must work as well as GET: most clients use GET, a few POST.
func TestUpdateAcceptsPost(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	req := httptest.NewRequest(http.MethodPost, server.UpdatePath+"?myip=203.0.113.1", nil)
	req.SetBasicAuth("fritzbox", h.token)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}

	rec := httptest.NewRecorder()
	h.update.ServeHTTP(rec, req)

	asrt.Equal(http.StatusOK, rec.Code)
	asrt.Equal("good 203.0.113.1", strings.TrimSpace(rec.Body.String()))
}

// The FRITZ!Box <dualstack> and <ip6lanprefix> placeholders produce parameters
// protean does not use. Unknown parameters must be ignored rather than
// rejected, or a client sending extras would fail for no reason.
func TestUnknownParametersAreIgnored(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	status, body := h.send(t,
		"?hostname=dyn.example.org&myip=203.0.113.1&dualstack=1&ip6lanprefix=2001:db8::/64"+
			"&wildcard=NOCHG&mx=mail.example.org&backmx=NO&offline=NO",
		"fritzbox", h.token)

	asrt.Equal(http.StatusOK, status)
	asrt.Equal("good 203.0.113.1", body)

	records := h.fake.records()
	require.Len(t, records, 1, "only the address protean manages may be written")
	asrt.Equal(provider.TypeA, records[0].Type)
}
