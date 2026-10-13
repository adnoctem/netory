package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// BackendMode is how pivot authenticates to the backend.
type BackendMode string

// The backend modes. All three are supported because a backend-agnostic core
// cannot assume the one Shopware happens to use.
const (
	// BackendOAuth2 is the client-credentials grant: pivot fetches a token
	// and refreshes it before expiry.
	BackendOAuth2 BackendMode = "oauth2"

	// BackendBasic sends HTTP Basic credentials on every forward leg.
	BackendBasic BackendMode = "http-basic"

	// BackendAPIKey sends a static token in a configurable header, which is
	// what most APIs outside the OAuth2 world use.
	BackendAPIKey BackendMode = "api-key"
)

// BackendModes lists the supported modes, for help text and validation.
func BackendModes() []string {
	return []string{string(BackendOAuth2), string(BackendBasic), string(BackendAPIKey)}
}

// Valid reports whether m is a supported backend mode.
func (m BackendMode) Valid() bool {
	switch m {
	case BackendOAuth2, BackendBasic, BackendAPIKey:
		return true
	default:
		return false
	}
}

// DefaultAPIKeyHeader is where an api-key credential goes when the
// configuration does not say.
const DefaultAPIKeyHeader = "Authorization"

// DefaultTokenLeeway is how long before expiry a backend token is refreshed.
//
// A token that expires while a request is in flight is a 401 from the backend
// that the customer sees as pivot's failure, so the refresh happens early
// enough that an in-flight request cannot land after expiry.
const DefaultTokenLeeway = 60 * time.Second

// MaxTokenResponseBytes bounds a backend token response.
const MaxTokenResponseBytes = 64 << 10

// BackendConfig is one client's backend credentials.
//
// One set per pivot client: a customer's requests reach the
// backend as that customer's own integration, with that integration's
// permissions. It is the second of pivot's two access-control layers, and the only one that can
// see data reachable through an allowed entity's associations.
type BackendConfig struct {
	// Mode selects the credential kind.
	Mode BackendMode `json:"mode"`

	// TokenPath is the backend's token endpoint for oauth2 mode, relative to
	// the backend URL.
	TokenPath string `json:"token_path,omitempty"`

	// ClientID and ClientSecret are the oauth2 client credentials.
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`

	// Scope is an optional oauth2 scope.
	Scope string `json:"scope,omitempty"`

	// Username and Password are the http-basic credentials.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// Header and Key are the api-key header name and value. An empty Header
	// means DefaultAPIKeyHeader.
	Header string `json:"header,omitempty"`
	Key    string `json:"key,omitempty"`

	// KeyPrefix is prepended to Key in the header, for an API that wants
	// "Bearer <key>" or "token <key>" rather than the bare value.
	KeyPrefix string `json:"key_prefix,omitempty"`
}

// Validate reports whether the configuration is usable.
//
// Checked when a backend is configured rather than on the first forward leg,
// so a missing credential is an error at `backend add` and not a 502 the
// customer sees.
func (c BackendConfig) Validate() error {
	if !c.Mode.Valid() {
		return fmt.Errorf("%w: backend mode %q, supported are %s",
			ErrUnsupportedMode, c.Mode, strings.Join(BackendModes(), ", "))
	}

	switch c.Mode {
	case BackendOAuth2:
		if c.ClientID == "" || c.ClientSecret == "" {
			return errors.New("auth: oauth2 needs a client_id and a client_secret")
		}

		if c.TokenPath == "" {
			return errors.New("auth: oauth2 needs a token_path, such as /api/oauth/token")
		}

		if !strings.HasPrefix(c.TokenPath, "/") {
			return fmt.Errorf("auth: token_path %q must begin with /", c.TokenPath)
		}

	case BackendBasic:
		if c.Username == "" || c.Password == "" {
			return errors.New("auth: http-basic needs a username and a password")
		}

	case BackendAPIKey:
		if c.Key == "" {
			return errors.New("auth: api-key needs a key")
		}

		if header := c.HeaderName(); !validHeaderName(header) {
			return fmt.Errorf("auth: %q is not a usable header name", header)
		}
	}

	return nil
}

// HeaderName returns the api-key header, defaulted.
func (c BackendConfig) HeaderName() string {
	if c.Header == "" {
		return DefaultAPIKeyHeader
	}

	return c.Header
}

// validHeaderName reports whether a string is a legal HTTP field name.
//
// Checked because the name comes from configuration and goes into a header
// map. A name containing a colon or a newline would be a request-splitting
// primitive handed to whoever can run `backend add`.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}

	for i := 0; i < len(name); i++ {
		c := name[i]

		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_':
		default:
			return false
		}
	}

	return true
}

// Redacted renders the configuration for `backend list`, with every
// credential replaced.
func (c BackendConfig) Redacted() map[string]string {
	out := map[string]string{"mode": string(c.Mode)}

	switch c.Mode {
	case BackendOAuth2:
		out["token_path"] = c.TokenPath
		out["client_id"] = c.ClientID
		out["client_secret"] = redact(c.ClientSecret)

		if c.Scope != "" {
			out["scope"] = c.Scope
		}

	case BackendBasic:
		out["username"] = c.Username
		out["password"] = redact(c.Password)

	case BackendAPIKey:
		out["header"] = c.HeaderName()
		out["key"] = redact(c.Key)

		if c.KeyPrefix != "" {
			out["key_prefix"] = c.KeyPrefix
		}
	}

	return out
}

// redact reports whether a credential is set without showing it.
func redact(value string) string {
	if value == "" {
		return "(unset)"
	}

	return "(set)"
}

// TokenCache shares backend tokens between replicas.
//
// An interface rather than a Valkey call, so this package stays free of the
// store - and so a test can exercise the refresh logic without one. The app
// layer implements it over an encrypted Valkey namespace, because a backend
// token is a credential, and so among the values pivot encrypts itself,
// Valkey having no encryption at rest.
//
// Shared across replicas and not merely cached locally, which is the point.
// Each replica fetching its own token would multiply token requests by the
// replica count and, on a backend that invalidates a previous token when it
// issues a new one, would have replicas revoking each other's.
type TokenCache interface {
	// Get returns a cached token and its expiry. A miss is (nil, false, nil).
	Get(ctx context.Context, clientID string) (token string, expiry time.Time, ok bool, err error)

	// Put stores a token until its expiry.
	Put(ctx context.Context, clientID, token string, expiry time.Time) error
}

// Backend puts pivot's credentials on an outbound request.
type Backend interface {
	// Mode is the credential kind, for logs and `backend list`.
	Mode() BackendMode

	// Authorize sets the credentials on req. It may make a network call - the
	// oauth2 mode fetches a token - so it takes a context and can fail.
	Authorize(ctx context.Context, req *http.Request) error
}

// BackendOptions are the dependencies an oauth2 backend needs.
type BackendOptions struct {
	// BaseURL is the backend origin, used to resolve TokenPath.
	BaseURL string

	// ClientKey identifies the pivot client these credentials belong to, and
	// is the token cache's key. Tokens must not be shared between pivot
	// clients: two customers' requests reaching the backend under one
	// integration would collapse the second access-control layer entirely.
	ClientKey string

	// Cache shares tokens across replicas. Nil means each process keeps its
	// own, which is correct only in a single-replica deployment.
	Cache TokenCache

	// HTTPClient makes the token request. Nil means http.DefaultClient.
	HTTPClient *http.Client

	// Leeway overrides DefaultTokenLeeway.
	Leeway time.Duration

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// NewBackend builds a Backend from configuration.
func NewBackend(cfg BackendConfig, opts BackendOptions) (Backend, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	switch cfg.Mode {
	case BackendBasic:
		return &basicBackend{cfg: cfg}, nil

	case BackendAPIKey:
		return &apiKeyBackend{cfg: cfg}, nil

	case BackendOAuth2:
		if opts.BaseURL == "" {
			return nil, errors.New("auth: oauth2 needs the backend base URL")
		}

		if opts.ClientKey == "" {
			return nil, errors.New("auth: oauth2 needs the pivot client it belongs to")
		}

		backend := &oauth2Backend{
			cfg:       cfg,
			baseURL:   strings.TrimSuffix(opts.BaseURL, "/"),
			clientKey: opts.ClientKey,
			cache:     opts.Cache,
			http:      opts.HTTPClient,
			leeway:    opts.Leeway,
			now:       opts.Now,
		}

		if backend.http == nil {
			backend.http = http.DefaultClient
		}

		if backend.leeway <= 0 {
			backend.leeway = DefaultTokenLeeway
		}

		if backend.now == nil {
			backend.now = time.Now
		}

		return backend, nil

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedMode, cfg.Mode)
	}
}

// basicBackend sends HTTP Basic credentials.
type basicBackend struct{ cfg BackendConfig }

func (b *basicBackend) Mode() BackendMode { return BackendBasic }

func (b *basicBackend) Authorize(_ context.Context, req *http.Request) error {
	req.SetBasicAuth(b.cfg.Username, b.cfg.Password)

	return nil
}

// apiKeyBackend sends a static key in a header.
type apiKeyBackend struct{ cfg BackendConfig }

func (a *apiKeyBackend) Mode() BackendMode { return BackendAPIKey }

func (a *apiKeyBackend) Authorize(_ context.Context, req *http.Request) error {
	value := a.cfg.Key
	if a.cfg.KeyPrefix != "" {
		value = a.cfg.KeyPrefix + " " + value
	}

	// Set rather than Add: the client's own Authorization header has already
	// been stripped by the forward leg, and a second value would leave the
	// backend choosing between two credentials.
	req.Header.Set(a.cfg.HeaderName(), value)

	return nil
}

// oauth2Backend fetches and refreshes a client-credentials token.
type oauth2Backend struct {
	cfg       BackendConfig
	baseURL   string
	clientKey string
	cache     TokenCache
	http      *http.Client
	leeway    time.Duration
	now       func() time.Time

	// mu serialises refreshes within one replica, so a burst of requests
	// arriving with an expired token makes one token request rather than one
	// per request. Across replicas the cache does the same job; this is the
	// in-process half.
	mu sync.Mutex

	// token and expiry are this replica's copy, checked before the cache to
	// keep the common path free of a Valkey round trip.
	token  string
	expiry time.Time
}

func (o *oauth2Backend) Mode() BackendMode { return BackendOAuth2 }

func (o *oauth2Backend) Authorize(ctx context.Context, req *http.Request) error {
	token, err := o.accessToken(ctx)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

// accessToken returns a valid token, fetching or refreshing as needed.
//
// The order is: this replica's copy, then the shared cache, then the backend.
// Checking locally first keeps the hot path free of a Valkey round trip;
// checking the cache before fetching is what stops every replica asking the
// backend for its own token.
func (o *oauth2Backend) accessToken(ctx context.Context) (string, error) {
	if token, ok := o.localToken(); ok {
		return token, nil
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	// Re-checked under the lock: a burst of requests all found the token
	// expired, and only the first should fetch.
	if o.token != "" && o.now().Add(o.leeway).Before(o.expiry) {
		return o.token, nil
	}

	if o.cache != nil {
		token, expiry, ok, err := o.cache.Get(ctx, o.clientKey)
		if err != nil {
			// A cache failure is logged by the caller and does not stop the
			// request: pivot can still fetch its own token, and a Valkey
			// hiccup should not turn into a customer-visible 502.
			token, ok = "", false
		}

		if ok && o.now().Add(o.leeway).Before(expiry) {
			o.token, o.expiry = token, expiry

			return token, nil
		}
	}

	token, expiry, err := o.fetch(ctx)
	if err != nil {
		return "", err
	}

	o.token, o.expiry = token, expiry

	if o.cache != nil {
		if err := o.cache.Put(ctx, o.clientKey, token, expiry); err != nil {
			// Same reasoning: the token is good, this replica will use it, and
			// the only cost is that another replica fetches its own.
			_ = err
		}
	}

	return token, nil
}

// localToken returns this replica's token when it is still good.
func (o *oauth2Backend) localToken() (string, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.token == "" {
		return "", false
	}

	if !o.now().Add(o.leeway).Before(o.expiry) {
		return "", false
	}

	return o.token, true
}

// fetch performs the client-credentials request.
func (o *oauth2Backend) fetch(ctx context.Context) (string, time.Time, error) {
	form := url.Values{}
	form.Set("grant_type", GrantClientCredentials)
	form.Set("client_id", o.cfg.ClientID)
	form.Set("client_secret", o.cfg.ClientSecret)

	if o.cfg.Scope != "" {
		form.Set("scope", o.cfg.Scope)
	}

	endpoint := o.baseURL + o.cfg.TokenPath

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: build the backend token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// The credentials also go in the Authorization header, because which
	// placement a backend accepts is not knowable in advance and RFC 6749
	// §2.3.1 makes Basic the one a server must support.
	req.SetBasicAuth(o.cfg.ClientID, o.cfg.ClientSecret)

	resp, err := o.http.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: fetch a backend token from %s: %w", endpoint, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxTokenResponseBytes))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: read the backend token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The backend's body is not echoed to the customer - it may name the
		// integration or the reason - but it is worth having in the error the
		// operator sees in the log.
		return "", time.Time{}, fmt.Errorf(
			"%w: %s answered %d: %s",
			ErrBackendRejected, endpoint, resp.StatusCode, summarise(body))
	}

	var response TokenResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", time.Time{}, fmt.Errorf(
			"auth: the backend token response from %s is not JSON: %w", endpoint, err)
	}

	if response.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf(
			"%w: %s returned no access_token", ErrBackendRejected, endpoint)
	}

	lifetime := time.Duration(response.ExpiresIn) * time.Second
	if lifetime <= 0 {
		// A backend that does not say gets a conservative assumption. Too
		// short only costs an extra token request; too long means using a
		// token the backend has already forgotten.
		lifetime = 10 * time.Minute
	}

	return response.AccessToken, o.now().Add(lifetime), nil
}

// ErrBackendRejected is returned when the backend refuses pivot's own
// credentials. It is distinct from a transport failure because the response is
// different: a rejected credential is a configuration problem that will not
// fix itself, and the backend.auth_failed event exists for it.
var ErrBackendRejected = errors.New("auth: the backend rejected pivot's credentials")

// summarise trims a backend error body for a log line.
func summarise(body []byte) string {
	const limit = 200

	text := strings.TrimSpace(string(body))
	text = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}

		return r
	}, text)

	if len(text) > limit {
		return text[:limit] + "…"
	}

	if text == "" {
		return "(empty body)"
	}

	return text
}
