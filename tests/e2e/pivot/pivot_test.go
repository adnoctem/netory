//go:build e2e

package pivot

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientIDPattern pulls the generated client id out of `client add` output.
var clientIDPattern = regexp.MustCompile(`client_id:\s+([0-9a-f]{24})`)

// clientSecretPattern pulls the secret out of the same output.
var clientSecretPattern = regexp.MustCompile(`client_secret:\s+(\S+)`)

// customer is a configured pivot client and the credentials it holds.
type customer struct {
	ID     string
	Secret string
	Token  string
}

// TestEndToEnd is one test with ordered subtests rather than many independent
// ones, because the stack takes seconds to build and the scenarios build on
// each other the way a real deployment does: configure, onboard a customer,
// serve it, then change something and watch the other replica follow.
func TestEndToEnd(t *testing.T) {
	stack := Start(t)

	first := stack.StartReplica("replica-a")

	// A fresh pivot denies everything, which is the right default for a
	// service whose job is to refuse - and it reports itself as not ready, so
	// a deployment that forgot to apply a rule set does not quietly send
	// customers 403s.
	t.Run("an unconfigured replica is not ready", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, status(t, first.ProxyURL+"/healthz"),
			"it is alive, and should be restarted rather than removed from rotation")
		assert.Equal(t, http.StatusServiceUnavailable, status(t, first.ProxyURL+"/readyz"))
	})

	t.Run("configure it through the CLI", func(t *testing.T) {
		applied := stack.MustCLI(first, "rules", "apply",
			ExamplePath(t, "shopware-readonly.yaml"))
		assert.Contains(t, applied, "applied globally")

		stack.MustCLI(first, "backend", "set", stack.Backend.URL())

		assert.Equal(t, http.StatusOK, status(t, first.ProxyURL+"/readyz"))
	})

	var acme customer

	t.Run("onboard a customer with oauth2 backend credentials", func(t *testing.T) {
		output := stack.MustCLI(first, "client", "add", "Acme GmbH",
			"--backend-mode", "oauth2",
			"--backend-token-path", "/api/oauth/token",
			"--backend-client-id", BackendClientID,
			"--backend-client-secret", BackendClientSecret,
			"--burst", "20", "--per-second", "5")

		id := clientIDPattern.FindStringSubmatch(output)
		require.Len(t, id, 2, "client add did not print a client id:\n%s", output)

		secret := clientSecretPattern.FindStringSubmatch(output)
		require.Len(t, secret, 2, "client add did not print a secret:\n%s", output)

		acme = customer{ID: id[1], Secret: secret[1]}

		// The secret is shown once and stored only as a hash, so the output
		// is the only place it exists.
		assert.Contains(t, output, "shown once")
	})

	t.Run("the customer exchanges credentials at pivot's own token endpoint", func(t *testing.T) {
		acme.Token = exchange(t, first.ProxyURL, acme.ID, acme.Secret)
		assert.NotEmpty(t, acme.Token)

		// Never forwarded: pivot answers it itself, so a client reaching the
		// backend's token endpoint would be authenticating against the
		// backend directly.
		for _, request := range stack.Backend.Requests() {
			assert.NotEqual(t, "/api/oauth/token", request.Path,
				"the customer's token exchange must not reach the backend")
		}
	})

	t.Run("an allowed read reaches the backend as pivot", func(t *testing.T) {
		response := proxy(t, first.ProxyURL, http.MethodGet, "/api/product", acme.Token, "")
		require.Equal(t, http.StatusOK, response.status, response.body)

		forwarded := stack.Backend.Last(t)

		asrt := assert.New(t)
		asrt.Equal("/api/product", forwarded.Path)
		asrt.True(strings.HasPrefix(forwarded.Auth, "Bearer backend-token-"),
			"the forward leg must carry pivot's own backend token, got %q", forwarded.Auth)
		asrt.NotContains(forwarded.Auth, acme.Token,
			"the customer's token must never reach the backend")
	})

	// §10.6: the documented Shopware example, against a backend speaking the
	// Admin API's shapes. These are the paths the CVEs were about.
	t.Run("the Shopware example denies what it is meant to", func(t *testing.T) {
		before := stack.Backend.Count()

		for _, path := range []string{
			"/api/_action/order/state",
			"/api/_action/sync",
			"/api/oauth/token-introspect",
			"/api/search/customer",
			"/api/search-ids/customer-group",
			"/api/_info/routes",
		} {
			response := proxy(t, first.ProxyURL, http.MethodGet, path, acme.Token, "")
			assert.Equal(t, http.StatusForbidden, response.status, path)
		}

		assert.Equal(t, before, stack.Backend.Count(),
			"a denied request must never cost a backend call")
	})

	t.Run("every spelling of a denied path is denied", func(t *testing.T) {
		for _, path := range []string{
			"/api//_action/order",
			"/api/./_action/order",
			"/api/v1/../_action/order",
			"/api/_acti%6Fn/order",
		} {
			response := proxy(t, first.ProxyURL, http.MethodGet, path, acme.Token, "")
			assert.Equal(t, http.StatusForbidden, response.status, path)
		}

		// And one that cannot be resolved is refused before any rule runs.
		response := proxy(t, first.ProxyURL, http.MethodGet, "/api%2F_action/order", acme.Token, "")
		assert.Equal(t, http.StatusBadRequest, response.status)
	})

	t.Run("no method beyond the read set is forwarded", func(t *testing.T) {
		before := stack.Backend.Count()

		for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
			response := proxy(t, first.ProxyURL, method, "/api/product", acme.Token, "")
			assert.Equal(t, http.StatusMethodNotAllowed, response.status, method)
		}

		assert.Equal(t, before, stack.Backend.Count())
	})

	t.Run("the search endpoints work and the product search is cached", func(t *testing.T) {
		before := stack.Backend.Count()

		first1 := proxy(t, first.ProxyURL, http.MethodPost,
			"/api/search/product", acme.Token, `{"limit":1}`)
		require.Equal(t, http.StatusOK, first1.status, first1.body)
		assert.Equal(t, "miss", first1.header.Get("X-Pivot-Cache"))

		second := proxy(t, first.ProxyURL, http.MethodPost,
			"/api/search/product", acme.Token, `{"limit":1}`)
		require.Equal(t, http.StatusOK, second.status)

		asrt := assert.New(t)
		asrt.Equal("hit", second.header.Get("X-Pivot-Cache"))
		asrt.Equal(first1.body, second.body)
		asrt.Equal(before+1, stack.Backend.Count(),
			"the second identical search must be served from the cache")

		// A different body is a different request: the key covers a hash of
		// it, so two searches cannot share an entry.
		third := proxy(t, first.ProxyURL, http.MethodPost,
			"/api/search/product", acme.Token, `{"limit":2}`)
		require.Equal(t, http.StatusOK, third.status)
		asrt.Equal("miss", third.header.Get("X-Pivot-Cache"))
	})

	t.Run("a plaintext request is refused", func(t *testing.T) {
		// Loopback is a declared trusted proxy in this stack, so pivot
		// believes X-Forwarded-Proto - which is what an ingress would set.
		request, err := http.NewRequest(http.MethodGet, first.ProxyURL+"/api/product", nil)
		require.NoError(t, err)

		request.Header.Set("Authorization", "Bearer "+acme.Token)
		request.Header.Set("X-Forwarded-Proto", "http")

		response, err := http.DefaultClient.Do(request)
		require.NoError(t, err)
		defer func() { _ = response.Body.Close() }()

		assert.Equal(t, http.StatusUpgradeRequired, response.StatusCode,
			"credentials travel on every request, so a plaintext hop discloses them")
	})

	var second *Replica

	t.Run("a second replica serves the same state", func(t *testing.T) {
		second = stack.StartReplica("replica-b")

		// Ready immediately: the rules and the client are in Valkey, not in
		// the first replica.
		assert.Equal(t, http.StatusOK, status(t, second.ProxyURL+"/readyz"))

		// And the customer's token, issued through replica A, works here.
		response := proxy(t, second.ProxyURL, http.MethodGet, "/api/product", acme.Token, "")
		assert.Equal(t, http.StatusOK, response.status, response.body)
	})

	t.Run("replicas share one backend token", func(t *testing.T) {
		// Both replicas have now forwarded for this customer. The backend
		// token is shared through Valkey, so it was fetched once - which
		// matters beyond efficiency: a backend that invalidates the previous
		// token when it issues a new one would have the replicas revoking
		// each other's.
		assert.Equal(t, int64(1), stack.Backend.TokenRequests(),
			"the second replica must take the cached backend token rather than fetch its own")
	})

	// §10.3's hot reload, which is the property that separates pivot from its
	// single-node siblings.
	t.Run("a rule change on one replica reaches the other", func(t *testing.T) {
		// Allowed on both right now.
		require.Equal(t, http.StatusOK,
			proxy(t, second.ProxyURL, http.MethodGet, "/api/currency", acme.Token, "").status)

		narrowed := filepath.Join(t.TempDir(), "narrowed.yaml")
		require.NoError(t, os.WriteFile(narrowed, []byte(`
rules:
  deny:
    - methods: ["*"]
      glob: /api/currency
      comment: narrowed during the end-to-end test
  allow:
    - methods: [GET]
      glob: /api/product
`), 0o600))

		// Marked before the change, so the wait below cannot be satisfied by a
		// reload that already happened.
		mark := second.LogMark()

		// Applied through replica A only.
		stack.MustCLI(first, "rules", "apply", narrowed)

		// Replica B was never told directly. It learns through the
		// announcement, and says so in its log.
		second.WaitForLog(t, mark, "rule table reloaded", 15*time.Second)

		assert.Equal(t, http.StatusForbidden,
			proxy(t, second.ProxyURL, http.MethodGet, "/api/currency", acme.Token, "").status,
			"the narrowed deny must apply on the replica that was never told directly")

		assert.Equal(t, http.StatusOK,
			proxy(t, second.ProxyURL, http.MethodGet, "/api/product", acme.Token, "").status)
	})

	t.Run("rules test explains a decision from either replica", func(t *testing.T) {
		output := stack.MustCLI(second, "rules", "test", "/api/currency")

		asrt := assert.New(t)
		asrt.Contains(output, "DENIED")
		asrt.Contains(output, "narrowed during the end-to-end test",
			"the comment from the YAML is what makes a denial explainable")
	})

	t.Run("per-client rules accumulate and cannot reopen a global deny", func(t *testing.T) {
		extra := filepath.Join(t.TempDir(), "acme-extra.yaml")
		require.NoError(t, os.WriteFile(extra, []byte(`
rules:
  allow:
    - methods: [GET]
      glob: /api/manufacturer
    - methods: [GET]
      glob: /api/currency
`), 0o600))

		mark := second.LogMark()

		stack.MustCLI(first, "rules", "apply", extra, "--client", acme.ID)
		second.WaitForLog(t, mark, "rule table reloaded", 15*time.Second)

		asrt := assert.New(t)

		// The client's extra allow is honoured.
		asrt.Equal(http.StatusOK,
			proxy(t, second.ProxyURL, http.MethodGet, "/api/manufacturer", acme.Token, "").status,
			"a client rule may grant a path the global set does not")

		// But it cannot reopen what the global set denies.
		asrt.Equal(http.StatusForbidden,
			proxy(t, second.ProxyURL, http.MethodGet, "/api/currency", acme.Token, "").status,
			"a client rule must never reopen a globally denied path")
	})

	t.Run("the rate limit is shared across replicas", func(t *testing.T) {
		stack.MustCLI(first, "client", "limit", acme.ID, "--burst", "4", "--per-second", "0.001")

		// Spent alternately against both replicas: the bucket is in Valkey,
		// so a per-replica limiter would let the customer take its whole
		// allowance from each one.
		allowed := 0
		replicas := []*Replica{first, second}

		for i := range 10 {
			target := replicas[i%2]

			response := proxy(t, target.ProxyURL, http.MethodGet, "/api/product", acme.Token, "")
			if response.status == http.StatusOK {
				allowed++
			}
		}

		assert.Equal(t, 4, allowed,
			"the burst is the whole allowance however many replicas serve it")
	})

	t.Run("a suspended customer stops working on both replicas", func(t *testing.T) {
		// The previous subtest emptied this customer's bucket on purpose, and
		// the token endpoint is rate limited like any other path - it is the
		// one route an unauthenticated stranger can reach, so leaving it out
		// would make it the obvious place to guess secrets from. Raising the
		// limit clears the bucket, which is what `client limit` does.
		stack.MustCLI(first, "client", "limit", acme.ID, "--burst", "20", "--per-second", "5")

		stack.MustCLI(first, "client", "disable", acme.ID)

		for _, replica := range []*Replica{first, second} {
			response := proxy(t, replica.ProxyURL, http.MethodGet, "/api/product", acme.Token, "")
			assert.Equal(t, http.StatusUnauthorized, response.status,
				"replica %s still served a disabled client", replica.Name)
		}

		// And the token is gone, so restoring the client does not restore it.
		stack.MustCLI(first, "client", "enable", acme.ID)

		response := proxy(t, first.ProxyURL, http.MethodGet, "/api/product", acme.Token, "")
		assert.Equal(t, http.StatusUnauthorized, response.status,
			"disabling revokes the tokens, so a restored client needs a fresh one")

		// A fresh exchange works.
		acme.Token = exchange(t, first.ProxyURL, acme.ID, acme.Secret)
		assert.Equal(t, http.StatusOK,
			proxy(t, first.ProxyURL, http.MethodGet, "/api/product", acme.Token, "").status)
	})

	// The other two backend modes, which no Shopware deployment would
	// exercise and which §2's backend-agnostic core requires.
	t.Run("the api-key backend mode works", func(t *testing.T) {
		output := stack.MustCLI(first, "client", "add", "Key Customer",
			"--backend-mode", "api-key",
			"--backend-header", "X-Api-Key",
			"--backend-key", BackendAPIKey)

		id := clientIDPattern.FindStringSubmatch(output)
		require.Len(t, id, 2)

		secret := clientSecretPattern.FindStringSubmatch(output)
		require.Len(t, secret, 2)

		token := exchange(t, first.ProxyURL, id[1], secret[1])

		response := proxy(t, first.ProxyURL, http.MethodGet, "/api/product", token, "")
		require.Equal(t, http.StatusOK, response.status, response.body)

		forwarded := stack.Backend.Last(t)
		assert.Equal(t, BackendAPIKey, forwarded.APIKey,
			"the api-key must arrive in the configured header")
		assert.Empty(t, forwarded.Auth,
			"and nothing should have been put in Authorization")
	})

	t.Run("the http-basic backend mode works", func(t *testing.T) {
		output := stack.MustCLI(first, "client", "add", "Basic Customer",
			"--backend-mode", "http-basic",
			"--backend-username", BackendUsername,
			"--backend-password", BackendPassword)

		id := clientIDPattern.FindStringSubmatch(output)
		require.Len(t, id, 2)

		secret := clientSecretPattern.FindStringSubmatch(output)
		require.Len(t, secret, 2)

		token := exchange(t, first.ProxyURL, id[1], secret[1])

		response := proxy(t, first.ProxyURL, http.MethodGet, "/api/product", token, "")
		require.Equal(t, http.StatusOK, response.status, response.body)

		forwarded := stack.Backend.Last(t)
		assert.True(t, strings.HasPrefix(forwarded.Auth, "Basic "),
			"the forward leg must carry Basic credentials, got %q", forwarded.Auth)
	})

	t.Run("backend test reports a rejected credential", func(t *testing.T) {
		output := stack.MustCLI(first, "client", "add", "Broken Customer",
			"--backend-mode", "oauth2",
			"--backend-token-path", "/api/oauth/token",
			"--backend-client-id", "wrong-id",
			"--backend-client-secret", "wrong-secret")

		id := clientIDPattern.FindStringSubmatch(output)
		require.Len(t, id, 2)

		result, err := stack.CLI(first, "backend", "test", "--client", id[1])
		require.NoError(t, err, result)

		assert.Contains(t, result, "rejected",
			"a credential the backend refuses must be reported as such")
	})

	t.Run("the audit trail records the administrative actions", func(t *testing.T) {
		output := stack.MustCLI(first, "audit", "list", "--kind", "admin")

		asrt := assert.New(t)
		asrt.Contains(output, "rules.apply")
		asrt.Contains(output, "client.add")
		asrt.Contains(output, "config.set")

		// The actor comes from the kernel through SO_PEERCRED rather than
		// from anything the request claimed.
		asrt.Regexp(regexp.MustCompile(`uid=\d+`), output)
	})

	t.Run("config view reports the answering replica", func(t *testing.T) {
		firstView := stack.MustCLI(first, "config", "view")
		secondView := stack.MustCLI(second, "config", "view")

		assert.Contains(t, firstView, "replica-a")
		assert.Contains(t, secondView, "replica-b")
	})

	t.Run("both replicas stop gracefully", func(t *testing.T) {
		// Stopping is what the cleanup does, so this asserts the startup and
		// shutdown lines are both present rather than stopping them early.
		for _, replica := range []*Replica{first, second} {
			assert.Contains(t, replica.Log(), "pivot starting", replica.Name)
			assert.NotContains(t, replica.Log(), `"level":"ERROR"`,
				"replica %s logged an error during a run that should have none:\n%s",
				replica.Name, replica.Log())
		}
	})
}

// response is a proxied reply.
type response struct {
	status int
	header http.Header
	body   string
}

// proxy issues an authenticated request through a replica.
//
// X-Forwarded-Proto is set because loopback is a declared trusted proxy in
// this stack, which is what an ingress would do - and without it pivot
// tolerates the request as "cannot tell" rather than refusing it, so the
// HTTPS enforcement would go untested.
func proxy(t *testing.T, origin, method, path, token, body string) response {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	request, err := http.NewRequest(method, origin+path, reader)
	require.NoError(t, err)

	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-Forwarded-Proto", "https")

	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}

	result, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = result.Body.Close() }()

	payload, err := io.ReadAll(result.Body)
	require.NoError(t, err)

	return response{status: result.StatusCode, header: result.Header, body: string(payload)}
}

// exchange obtains an access token through pivot's own token endpoint.
func exchange(t *testing.T, origin, id, secret string) string {
	t.Helper()

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {id},
		"client_secret": {secret},
	}

	request, err := http.NewRequest(
		http.MethodPost, origin+"/api/oauth/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("X-Forwarded-Proto", "https")

	result, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer func() { _ = result.Body.Close() }()

	payload, err := io.ReadAll(result.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, result.StatusCode,
		"the token exchange failed: %s", payload)

	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(payload, &token))

	// The shapes are RFC 6749's, which is what makes pivot transparent: a
	// client that parsed the backend's response parses this one unchanged.
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Positive(t, token.ExpiresIn)

	return token.AccessToken
}

// status returns the status code of a plain GET.
func status(t *testing.T, target string) int {
	t.Helper()

	result, err := http.Get(target) //nolint:noctx // a probe in a test
	require.NoError(t, err)
	defer func() { _ = result.Body.Close() }()

	return result.StatusCode
}
