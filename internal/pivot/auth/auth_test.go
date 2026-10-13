package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/auth"
)

func TestGeneratedCredentialsAreDistinctAndLongEnough(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}

	for range 100 {
		secret, err := auth.GenerateSecret()
		require.NoError(t, err)
		require.False(t, seen[secret], "a generated secret repeated")
		seen[secret] = true

		// 32 bytes base64url without padding is 43 characters.
		assert.Len(t, secret, 43)
	}

	id, err := auth.GenerateClientID()
	require.NoError(t, err)
	assert.Len(t, id, 24, "12 bytes as hex")

	token, err := auth.GenerateToken()
	require.NoError(t, err)
	assert.Len(t, token, 43)
}

func TestHashAndEqual(t *testing.T) {
	t.Parallel()

	asrt := assert.New(t)

	hash := auth.Hash("a-secret")
	asrt.Len(hash, 64, "hex SHA-256")
	asrt.Equal(hash, auth.Hash("a-secret"))
	asrt.NotEqual(hash, auth.Hash("a-secret "))

	asrt.True(auth.Equal(hash, auth.Hash("a-secret")))
	asrt.False(auth.Equal(hash, auth.Hash("another-secret")))
	asrt.False(auth.Equal(hash, ""))
}

// A credential must not have a rendering that includes its secret, because a
// type like that eventually gets printed by accident.
func TestRedactedNeverCarriesTheSecret(t *testing.T) {
	t.Parallel()

	secret := auth.Credential{
		Kind:     auth.KindClientSecret,
		ClientID: "abc123",
		Secret:   "the-actual-secret",
	}

	rendered := secret.Redacted()
	assert.Contains(t, rendered, "abc123")
	assert.NotContains(t, rendered, "the-actual-secret")

	token := auth.Credential{Kind: auth.KindToken, Token: "the-actual-token"}

	rendered = token.Redacted()
	assert.NotContains(t, rendered, "the-actual-token")
	assert.Contains(t, rendered, auth.Hash("the-actual-token")[:16],
		"a truncated hash identifies the credential across log lines without being one")
}

func TestExtractCredential(t *testing.T) {
	t.Parallel()

	t.Run("bearer modes", func(t *testing.T) {
		t.Parallel()

		for _, mode := range []auth.FrontendMode{auth.FrontendOAuth2, auth.FrontendBearer} {
			req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
			req.Header.Set("Authorization", "Bearer the-token")

			credential, err := auth.ExtractCredential(mode, req)
			require.NoError(t, err, mode)

			assert.Equal(t, auth.KindToken, credential.Kind)
			assert.Equal(t, "the-token", credential.Token)
		}
	})

	t.Run("basic mode", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
		req.SetBasicAuth("client-id", "client-secret")

		credential, err := auth.ExtractCredential(auth.FrontendBasic, req)
		require.NoError(t, err)

		assert.Equal(t, auth.KindClientSecret, credential.Kind)
		assert.Equal(t, "client-id", credential.ClientID)
		assert.Equal(t, "client-secret", credential.Secret)
	})

	t.Run("a missing credential is distinct from a bad one", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/api/product", nil)

		_, err := auth.ExtractCredential(auth.FrontendOAuth2, req)
		assert.ErrorIs(t, err, auth.ErrNoCredential,
			"the audit log needs to tell a misconfigured client from something probing")
	})

	t.Run("malformed credentials", func(t *testing.T) {
		t.Parallel()

		for name, header := range map[string]string{
			"wrong scheme for bearer": "Basic " + base64.StdEncoding.EncodeToString([]byte("a:b")),
			"empty bearer":            "Bearer   ",
		} {
			req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
			req.Header.Set("Authorization", header)

			_, err := auth.ExtractCredential(auth.FrontendOAuth2, req)
			assert.ErrorIs(t, err, auth.ErrMalformedCredential, name)
		}

		for name, header := range map[string]string{
			"wrong scheme for basic": "Bearer a-token",
			"not base64":             "Basic not-base64!!",
			"no colon":               "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")),
			"empty secret":           "Basic " + base64.StdEncoding.EncodeToString([]byte("id:")),
		} {
			req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
			req.Header.Set("Authorization", header)

			_, err := auth.ExtractCredential(auth.FrontendBasic, req)
			assert.ErrorIs(t, err, auth.ErrMalformedCredential, name)
		}
	})

	t.Run("an unknown mode is an error rather than a default", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
		req.Header.Set("Authorization", "Bearer x")

		_, err := auth.ExtractCredential("magic", req)
		assert.ErrorIs(t, err, auth.ErrUnsupportedMode)
	})
}

// Both credential placements must work: RFC 6749 §2.3.1 requires Basic and
// Shopware's own clients send the body form, so rejecting either would break
// "existing clients work unchanged".
func TestParseTokenRequestAcceptsBothPlacements(t *testing.T) {
	t.Parallel()

	t.Run("body form", func(t *testing.T) {
		t.Parallel()

		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"the-id"},
			"client_secret": {"the-secret"},
		}

		req := tokenRequest(form, "", "")

		parsed, err := auth.ParseTokenRequest(req)
		require.NoError(t, err)

		assert.Equal(t, "the-id", parsed.ClientID)
		assert.Equal(t, "the-secret", parsed.ClientSecret)
		assert.Equal(t, auth.GrantClientCredentials, parsed.GrantType)
	})

	t.Run("basic header", func(t *testing.T) {
		t.Parallel()

		req := tokenRequest(url.Values{"grant_type": {"client_credentials"}}, "the-id", "the-secret")

		parsed, err := auth.ParseTokenRequest(req)
		require.NoError(t, err)

		assert.Equal(t, "the-id", parsed.ClientID)
		assert.Equal(t, "the-secret", parsed.ClientSecret)
	})

	t.Run("basic wins over a matching body", func(t *testing.T) {
		t.Parallel()

		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"the-id"},
			"client_secret": {"body-secret"},
		}

		parsed, err := auth.ParseTokenRequest(tokenRequest(form, "the-id", "header-secret"))
		require.NoError(t, err)

		assert.Equal(t, "header-secret", parsed.ClientSecret, "RFC 6749 §2.3.1 prefers the header")
	})

	// Two different client ids in one request is a confused client. Silently
	// preferring one makes the confusion somebody else's problem later.
	t.Run("two different client ids are refused", func(t *testing.T) {
		t.Parallel()

		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {"body-id"},
			"client_secret": {"body-secret"},
		}

		_, err := auth.ParseTokenRequest(tokenRequest(form, "header-id", "header-secret"))
		assert.ErrorIs(t, err, auth.ErrMalformedCredential)
	})
}

func TestParseTokenRequestRejections(t *testing.T) {
	t.Parallel()

	t.Run("GET", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/api/oauth/token", nil)

		_, err := auth.ParseTokenRequest(req)
		assert.ErrorIs(t, err, auth.ErrMalformedCredential)
	})

	t.Run("no grant type", func(t *testing.T) {
		t.Parallel()

		form := url.Values{"client_id": {"a"}, "client_secret": {"b"}}

		_, err := auth.ParseTokenRequest(tokenRequest(form, "", ""))
		assert.ErrorIs(t, err, auth.ErrMalformedCredential)
	})

	t.Run("no credentials", func(t *testing.T) {
		t.Parallel()

		form := url.Values{"grant_type": {"client_credentials"}}

		_, err := auth.ParseTokenRequest(tokenRequest(form, "", ""))
		assert.ErrorIs(t, err, auth.ErrNoCredential)
	})

	// The token endpoint is the one path pivot answers before any client is
	// known, so it is the only place a stranger can make pivot allocate.
	t.Run("an oversized body is bounded", func(t *testing.T) {
		t.Parallel()

		body := "grant_type=client_credentials&client_id=a&client_secret=" +
			strings.Repeat("x", auth.MaxTokenRequestBytes*2)

		req := httptest.NewRequest(http.MethodPost, "/api/oauth/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := auth.ParseTokenRequest(req)
		assert.ErrorIs(t, err, auth.ErrMalformedCredential)
	})
}

func tokenRequest(form url.Values, basicID, basicSecret string) *http.Request {
	req := httptest.NewRequest(
		http.MethodPost, "/api/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if basicID != "" || basicSecret != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}

	return req
}

// The response shape is RFC 6749 §5.1's, which is also Shopware's, so a client
// that parsed the backend's response parses pivot's unchanged.
func TestTokenResponseShape(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	auth.WriteTokenResponse(recorder, auth.NewTokenResponse("the-token", 10*time.Minute, ""))

	asrt := assert.New(t)
	asrt.Equal(http.StatusOK, recorder.Code)
	asrt.Equal("application/json; charset=utf-8", recorder.Header().Get("Content-Type"))
	asrt.Equal("no-store", recorder.Header().Get("Cache-Control"),
		"a cached token response is a credential sitting in an intermediary")

	var body map[string]any
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))

	asrt.Equal("the-token", body["access_token"])
	asrt.Equal("Bearer", body["token_type"])
	asrt.InDelta(600.0, body["expires_in"], 0, "expires_in is seconds, as the RFC requires")
}

// Whether the client id was unknown or the secret was wrong must not be
// distinguishable: telling an attacker which half of a guess was right turns
// one search space into two much smaller ones.
func TestInvalidClientRevealsNothing(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	auth.WriteError(recorder, http.StatusUnauthorized, auth.InvalidClient())

	asrt := assert.New(t)
	asrt.Equal(http.StatusUnauthorized, recorder.Code)
	asrt.Equal(`Basic realm="pivot"`, recorder.Header().Get("WWW-Authenticate"))

	var body auth.Error
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))

	asrt.Equal(auth.ErrorInvalidClient, body.Code)

	for _, word := range []string{"unknown", "not found", "secret", "password", "exist"} {
		asrt.NotContains(strings.ToLower(body.Description), word,
			"the description must not say which half of the credential was wrong")
	}
}

// A forwarded method-override header would let a client turn an allowed GET
// into a method the rules never evaluated.
func TestStripMethodOverride(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/api/product", nil)
	for _, header := range auth.MethodOverrideHeaders {
		req.Header.Set(header, "DELETE")
	}

	auth.StripMethodOverride(req)

	for _, header := range auth.MethodOverrideHeaders {
		assert.Empty(t, req.Header.Get(header), header)
	}
}

func TestBackendConfigValidation(t *testing.T) {
	t.Parallel()

	for name, cfg := range map[string]auth.BackendConfig{
		"unknown mode":        {Mode: "magic"},
		"oauth2 without id":   {Mode: auth.BackendOAuth2, ClientSecret: "s", TokenPath: "/t"},
		"oauth2 without path": {Mode: auth.BackendOAuth2, ClientID: "i", ClientSecret: "s"},
		"oauth2 relative path": {
			Mode: auth.BackendOAuth2, ClientID: "i", ClientSecret: "s", TokenPath: "token",
		},
		"basic without password": {Mode: auth.BackendBasic, Username: "u"},
		"api-key without key":    {Mode: auth.BackendAPIKey},
		// A header name from configuration goes into a header map, so a name
		// carrying a colon or a newline would be a request-splitting
		// primitive handed to whoever can run `backend add`.
		"api-key with a bad header": {
			Mode: auth.BackendAPIKey, Key: "k", Header: "X-Key: injected",
		},
		"api-key with a newline header": {
			Mode: auth.BackendAPIKey, Key: "k", Header: "X-Key\r\nX-Other",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Error(t, cfg.Validate())
		})
	}

	for name, cfg := range map[string]auth.BackendConfig{
		"oauth2": {
			Mode: auth.BackendOAuth2, ClientID: "i", ClientSecret: "s", TokenPath: "/api/oauth/token",
		},
		"basic":   {Mode: auth.BackendBasic, Username: "u", Password: "p"},
		"api-key": {Mode: auth.BackendAPIKey, Key: "k"},
		"api-key with a header": {
			Mode: auth.BackendAPIKey, Key: "k", Header: "X-Api-Key",
		},
	} {
		t.Run(name+" is valid", func(t *testing.T) {
			t.Parallel()

			assert.NoError(t, cfg.Validate())
		})
	}
}

func TestBackendConfigRedacted(t *testing.T) {
	t.Parallel()

	cases := []auth.BackendConfig{
		{Mode: auth.BackendOAuth2, ClientID: "i", ClientSecret: "the-secret", TokenPath: "/t"},
		{Mode: auth.BackendBasic, Username: "u", Password: "the-password"},
		{Mode: auth.BackendAPIKey, Key: "the-key"},
	}

	for _, cfg := range cases {
		redacted := cfg.Redacted()

		for key, value := range redacted {
			for _, secret := range []string{"the-secret", "the-password", "the-key"} {
				assert.NotContains(t, value, secret, "%s leaked through %s", cfg.Mode, key)
			}
		}
	}
}

func TestBasicBackend(t *testing.T) {
	t.Parallel()

	backend, err := auth.NewBackend(
		auth.BackendConfig{Mode: auth.BackendBasic, Username: "u", Password: "p"},
		auth.BackendOptions{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
	require.NoError(t, backend.Authorize(context.Background(), req))

	id, secret, ok := req.BasicAuth()
	require.True(t, ok)
	assert.Equal(t, "u", id)
	assert.Equal(t, "p", secret)
}

func TestAPIKeyBackend(t *testing.T) {
	t.Parallel()

	t.Run("default header", func(t *testing.T) {
		t.Parallel()

		backend, err := auth.NewBackend(
			auth.BackendConfig{Mode: auth.BackendAPIKey, Key: "the-key"},
			auth.BackendOptions{})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
		require.NoError(t, backend.Authorize(context.Background(), req))

		assert.Equal(t, "the-key", req.Header.Get("Authorization"))
	})

	t.Run("custom header and prefix", func(t *testing.T) {
		t.Parallel()

		backend, err := auth.NewBackend(
			auth.BackendConfig{
				Mode:      auth.BackendAPIKey,
				Key:       "the-key",
				Header:    "X-Api-Key",
				KeyPrefix: "token",
			},
			auth.BackendOptions{})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
		require.NoError(t, backend.Authorize(context.Background(), req))

		assert.Equal(t, "token the-key", req.Header.Get("X-Api-Key"))
	})

	// A client's own Authorization header is stripped by the forward leg, and
	// the credential is Set rather than Added, so the backend never has to
	// choose between two.
	t.Run("an existing header is replaced", func(t *testing.T) {
		t.Parallel()

		backend, err := auth.NewBackend(
			auth.BackendConfig{Mode: auth.BackendAPIKey, Key: "the-key"},
			auth.BackendOptions{})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
		req.Header.Add("Authorization", "Bearer customers-own-token")

		require.NoError(t, backend.Authorize(context.Background(), req))

		assert.Equal(t, []string{"the-key"}, req.Header.Values("Authorization"))
	})
}

// fakeCache is the app layer's TokenCache, in memory.
type fakeCache struct {
	mu      sync.Mutex
	tokens  map[string]cached
	failGet bool
	failPut bool
	puts    atomic.Int64
}

type cached struct {
	token  string
	expiry time.Time
}

func newFakeCache() *fakeCache { return &fakeCache{tokens: map[string]cached{}} }

func (f *fakeCache) Get(_ context.Context, clientID string) (string, time.Time, bool, error) {
	if f.failGet {
		return "", time.Time{}, false, assert.AnError
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	entry, ok := f.tokens[clientID]

	return entry.token, entry.expiry, ok, nil
}

func (f *fakeCache) Put(_ context.Context, clientID, token string, expiry time.Time) error {
	f.puts.Add(1)

	if f.failPut {
		return assert.AnError
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	f.tokens[clientID] = cached{token: token, expiry: expiry}

	return nil
}

// tokenServer stands in for the backend's token endpoint, counting requests.
func tokenServer(t *testing.T, lifetime int) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var requests atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)

		require.NoError(t, r.ParseForm())
		assert.Equal(t, auth.GrantClientCredentials, r.PostForm.Get("grant_type"))

		// The credentials must arrive in the header as well as the body,
		// since which placement a backend accepts is not knowable in advance.
		id, secret, ok := r.BasicAuth()
		assert.True(t, ok, "the token request must carry Basic credentials")
		assert.Equal(t, "backend-id", id)
		assert.Equal(t, "backend-secret", secret)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(auth.TokenResponse{
			AccessToken: "backend-token-" + strings.TrimSpace(string(rune('0'+n))),
			TokenType:   "Bearer",
			ExpiresIn:   lifetime,
		})
	}))

	t.Cleanup(server.Close)

	return server, &requests
}

func oauth2Backend(t *testing.T, baseURL string, cache auth.TokenCache, now func() time.Time) auth.Backend {
	t.Helper()

	backend, err := auth.NewBackend(
		auth.BackendConfig{
			Mode:         auth.BackendOAuth2,
			ClientID:     "backend-id",
			ClientSecret: "backend-secret",
			TokenPath:    "/api/oauth/token",
		},
		auth.BackendOptions{
			BaseURL:    baseURL,
			ClientKey:  "pivot-client-1",
			Cache:      cache,
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
			Now:        now,
		})
	require.NoError(t, err)

	return backend
}

func TestOAuth2BackendFetchesAndReuses(t *testing.T) {
	t.Parallel()

	server, requests := tokenServer(t, 600)
	backend := oauth2Backend(t, server.URL, newFakeCache(), nil)

	for range 5 {
		req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
		require.NoError(t, backend.Authorize(context.Background(), req))

		assert.True(t, strings.HasPrefix(req.Header.Get("Authorization"), "Bearer backend-token-"))
	}

	assert.Equal(t, int64(1), requests.Load(),
		"a valid token must be reused rather than re-fetched per request")
}

// A burst of requests arriving with no token must make one token request, not
// one per request. Without the in-process lock this is where a cold start
// stampedes the backend's token endpoint.
func TestOAuth2BackendCoalescesABurst(t *testing.T) {
	t.Parallel()

	server, requests := tokenServer(t, 600)
	backend := oauth2Backend(t, server.URL, newFakeCache(), nil)

	var wg sync.WaitGroup

	for range 32 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
			assert.NoError(t, backend.Authorize(context.Background(), req))
		}()
	}

	wg.Wait()

	assert.Equal(t, int64(1), requests.Load(),
		"32 concurrent requests with no token must produce one token request")
}

// The token is refreshed before it expires, not after: a token that expires
// mid-flight is a 401 from the backend that the customer sees as pivot's
// failure.
func TestOAuth2BackendRefreshesBeforeExpiry(t *testing.T) {
	t.Parallel()

	server, requests := tokenServer(t, 120)

	clock := time.Now()
	backend := oauth2Backend(t, server.URL, newFakeCache(), func() time.Time { return clock })

	req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
	require.NoError(t, backend.Authorize(context.Background(), req))
	require.Equal(t, int64(1), requests.Load())

	// Still inside the lifetime and outside the leeway: reused.
	clock = clock.Add(30 * time.Second)
	require.NoError(t, backend.Authorize(context.Background(), req))
	assert.Equal(t, int64(1), requests.Load())

	// Inside the leeway, so refreshed although the token has not expired.
	clock = clock.Add(60 * time.Second)
	require.NoError(t, backend.Authorize(context.Background(), req))
	assert.Equal(t, int64(2), requests.Load(),
		"the refresh must happen before expiry, not at it")
}

// The cache is what stops every replica fetching its own token. On a backend
// that invalidates the previous token when it issues a new one, replicas
// without a shared cache revoke each other's.
func TestOAuth2BackendSharesTokensThroughTheCache(t *testing.T) {
	t.Parallel()

	server, requests := tokenServer(t, 600)
	cache := newFakeCache()

	first := oauth2Backend(t, server.URL, cache, nil)

	req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
	require.NoError(t, first.Authorize(context.Background(), req))
	require.Equal(t, int64(1), requests.Load())

	// A second replica, with its own in-process state and the same cache.
	second := oauth2Backend(t, server.URL, cache, nil)

	other := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
	require.NoError(t, second.Authorize(context.Background(), other))

	assert.Equal(t, int64(1), requests.Load(),
		"the second replica must take the cached token rather than fetch its own")
	assert.Equal(t, req.Header.Get("Authorization"), other.Header.Get("Authorization"))
}

// A Valkey hiccup must not become a customer-visible failure: pivot can still
// fetch its own token, and the only cost is an extra token request.
func TestOAuth2BackendSurvivesACacheFailure(t *testing.T) {
	t.Parallel()

	server, requests := tokenServer(t, 600)

	cache := newFakeCache()
	cache.failGet = true
	cache.failPut = true

	backend := oauth2Backend(t, server.URL, cache, nil)

	req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
	require.NoError(t, backend.Authorize(context.Background(), req),
		"a cache failure must not fail the request")

	assert.Equal(t, int64(1), requests.Load())
	assert.NotEmpty(t, req.Header.Get("Authorization"))
}

// A rejected credential is a configuration problem that will not fix itself,
// so it is a distinct error from a transport failure - the
// backend.auth_failed event exists for exactly this.
func TestOAuth2BackendReportsRejection(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	t.Cleanup(server.Close)

	backend := oauth2Backend(t, server.URL, newFakeCache(), nil)

	req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
	err := backend.Authorize(context.Background(), req)

	require.ErrorIs(t, err, auth.ErrBackendRejected)
	assert.Contains(t, err.Error(), "401")
	assert.Empty(t, req.Header.Get("Authorization"), "a failed authorize must set no credential")
}

func TestOAuth2BackendRejectsABadResponse(t *testing.T) {
	t.Parallel()

	for name, handler := range map[string]http.HandlerFunc{
		"not JSON": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("not json at all"))
		},
		"no access token": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":600}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(handler)
			t.Cleanup(server.Close)

			backend := oauth2Backend(t, server.URL, newFakeCache(), nil)

			req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
			assert.Error(t, backend.Authorize(context.Background(), req))
		})
	}
}

// A backend that returns no expires_in gets a conservative assumption: too
// short costs an extra token request, too long means using a token the backend
// has already forgotten.
func TestOAuth2BackendAssumesAShortLifetime(t *testing.T) {
	t.Parallel()

	server, requests := tokenServer(t, 0)

	clock := time.Now()
	backend := oauth2Backend(t, server.URL, newFakeCache(), func() time.Time { return clock })

	req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
	require.NoError(t, backend.Authorize(context.Background(), req))

	// Reused well inside ten minutes.
	clock = clock.Add(5 * time.Minute)
	require.NoError(t, backend.Authorize(context.Background(), req))
	assert.Equal(t, int64(1), requests.Load())

	// And refreshed past it.
	clock = clock.Add(6 * time.Minute)
	require.NoError(t, backend.Authorize(context.Background(), req))
	assert.Equal(t, int64(2), requests.Load())
}

// Tokens must not be shared between pivot clients: two customers' requests
// reaching the backend under one integration would collapse the second of pivot's
// two access-control layers entirely.
func TestOAuth2BackendKeysTheCachePerClient(t *testing.T) {
	t.Parallel()

	server, _ := tokenServer(t, 600)
	cache := newFakeCache()

	first := oauth2Backend(t, server.URL, cache, nil)

	req := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
	require.NoError(t, first.Authorize(context.Background(), req))

	// A second pivot client with its own credentials and its own cache key.
	second, err := auth.NewBackend(
		auth.BackendConfig{
			Mode:         auth.BackendOAuth2,
			ClientID:     "backend-id",
			ClientSecret: "backend-secret",
			TokenPath:    "/api/oauth/token",
		},
		auth.BackendOptions{
			BaseURL:   server.URL,
			ClientKey: "pivot-client-2",
			Cache:     cache,
		})
	require.NoError(t, err)

	other := httptest.NewRequest(http.MethodGet, "https://backend.example/api/product", nil)
	require.NoError(t, second.Authorize(context.Background(), other))

	assert.Equal(t, int64(2), cache.puts.Load(),
		"each pivot client must get its own cached backend token")
}

func TestNewBackendRequiresItsDependencies(t *testing.T) {
	t.Parallel()

	cfg := auth.BackendConfig{
		Mode:         auth.BackendOAuth2,
		ClientID:     "i",
		ClientSecret: "s",
		TokenPath:    "/t",
	}

	_, err := auth.NewBackend(cfg, auth.BackendOptions{ClientKey: "c"})
	assert.Error(t, err, "oauth2 needs the backend base URL")

	_, err = auth.NewBackend(cfg, auth.BackendOptions{BaseURL: "https://b.example"})
	assert.Error(t, err, "oauth2 needs the pivot client it belongs to")
}
