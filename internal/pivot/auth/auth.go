// Package auth is pivot's two authentication sides.
//
// The two are separate, and so is this package. The frontend side
// decides which pivot client a customer request belongs to, from credentials
// pivot itself issued. The backend side puts pivot's own credentials on the
// forward leg. Neither knows about the other, and a customer never holds a
// backend credential - credentials never leave pivot.
//
// Nothing here touches Valkey. The frontend mechanics are header parsing,
// hashing and the OAuth2 wire shapes; the backend mechanics are setting an
// Authorization header and, in oauth2 mode, keeping a token fresh. Persistence
// is the app layer's, behind the two small interfaces this package declares,
// which is what lets the whole of it be tested without a store.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// SecretBytes and TokenBytes are the sizes of generated credentials.
//
// 32 bytes of entropy each, the same as protean's tokens. A pivot client
// secret and an access token are both bearer credentials that travel on every
// request, so neither has any business being shorter.
const (
	SecretBytes = 32
	TokenBytes  = 32
)

// ClientIDBytes is the size of a generated client identifier.
//
// Shorter than a secret because it is not one: the identifier is logged, shown
// in `client list`, and appears in audit records. It is long enough not to
// collide and short enough to read out.
const ClientIDBytes = 12

// Sentinel errors.
var (
	// ErrNoCredential is returned when a request carries no credentials at
	// all. Kept distinct from a wrong credential so the audit log can tell
	// "a client is misconfigured" from "something is probing".
	ErrNoCredential = errors.New("auth: the request carries no credentials")

	// ErrMalformedCredential is returned for credentials pivot cannot parse.
	ErrMalformedCredential = errors.New("auth: the credentials are malformed")

	// ErrUnsupportedMode is returned for an unknown auth mode.
	ErrUnsupportedMode = errors.New("auth: unsupported mode")
)

// GenerateSecret returns a new client secret.
func GenerateSecret() (string, error) { return randomString(SecretBytes) }

// GenerateToken returns a new opaque access token.
//
// Opaque rather than a JWT. A self-contained token cannot
// be revoked before it expires without a revocation list, which is a stored
// record per token - exactly the thing a JWT was supposed to avoid. An opaque
// token is already a lookup, so revoking it is deleting one key.
func GenerateToken() (string, error) { return randomString(TokenBytes) }

// GenerateClientID returns a new client identifier.
func GenerateClientID() (string, error) {
	buf := make([]byte, ClientIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate a client id: %w", err)
	}

	return hex.EncodeToString(buf), nil
}

// randomString returns n random bytes, base64url-encoded without padding.
func randomString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: generate %d random bytes: %w", n, err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Hash returns the hex SHA-256 of a credential.
//
// A plain hash rather than a password KDF, and the reason is the same one
// protean records for its tokens: these are 32 bytes of machine-generated
// entropy, not a human-chosen password. There is no dictionary to attack and
// nothing for bcrypt's work factor to slow down, while the hash is computed on
// every single request - a KDF here would be a per-request cost buying
// nothing. It would be the wrong choice for anything a person types.
func Hash(credential string) string {
	sum := sha256.Sum256([]byte(credential))

	return hex.EncodeToString(sum[:])
}

// Equal compares two hashes in constant time.
//
// The inputs are hashes of credentials rather than the credentials, so the
// comparison is not strictly timing-sensitive - but a credential check is
// exactly the place where that argument should not have to be made, and the
// constant-time compare costs nothing.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// FrontendMode is how customers authenticate to pivot.
type FrontendMode string

// The frontend modes.
const (
	// FrontendOAuth2 emulates the backend's client-credentials token
	// endpoint, so existing clients work unchanged against the backend's own
	// documentation.
	FrontendOAuth2 FrontendMode = "oauth2"

	// FrontendBasic takes the client id and secret as HTTP Basic credentials
	// on every request, with no token exchange.
	FrontendBasic FrontendMode = "http-basic"

	// FrontendBearer takes a long-lived token pivot issued, presented as a
	// bearer token with no exchange step.
	FrontendBearer FrontendMode = "bearer"
)

// FrontendModes lists the supported modes, for help text and validation.
func FrontendModes() []string {
	return []string{string(FrontendOAuth2), string(FrontendBasic), string(FrontendBearer)}
}

// Valid reports whether m is a supported frontend mode.
func (m FrontendMode) Valid() bool {
	switch m {
	case FrontendOAuth2, FrontendBasic, FrontendBearer:
		return true
	default:
		return false
	}
}

// CredentialKind says what a customer presented.
type CredentialKind string

// The credential kinds.
const (
	// KindClientSecret is a client id and secret pair, from HTTP Basic or an
	// OAuth2 token request body.
	KindClientSecret CredentialKind = "client-secret"

	// KindToken is a bearer token pivot issued.
	KindToken CredentialKind = "token"
)

// Credential is what a request presented, before it is resolved to a client.
type Credential struct {
	Kind CredentialKind

	// ClientID and Secret are set for KindClientSecret.
	ClientID string
	Secret   string

	// Token is set for KindToken.
	Token string
}

// Redacted renders the credential for a log line, with the secret removed.
//
// There is no String method on purpose: a type whose natural rendering
// includes a secret is one that eventually gets printed by accident, and the
// compiler will not warn about it.
func (c Credential) Redacted() string {
	switch c.Kind {
	case KindClientSecret:
		return "client-secret client_id=" + c.ClientID
	case KindToken:
		// The hash rather than the token: it identifies the credential in a
		// log without being usable as one, which is what makes correlating
		// two log lines possible without the log becoming a credential store.
		return "token sha256=" + Hash(c.Token)[:16]
	default:
		return "unknown"
	}
}

// parseBasic splits an HTTP Basic credential.
func parseBasic(header string) (id, secret string, err error) {
	const prefix = "Basic "

	if !strings.HasPrefix(header, prefix) {
		return "", "", ErrMalformedCredential
	}

	decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if decodeErr != nil {
		return "", "", fmt.Errorf("%w: Basic credentials are not base64", ErrMalformedCredential)
	}

	id, secret, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", fmt.Errorf("%w: Basic credentials carry no colon", ErrMalformedCredential)
	}

	return id, secret, nil
}

// parseBearer extracts a bearer token.
func parseBearer(header string) (string, error) {
	const prefix = "Bearer "

	if !strings.HasPrefix(header, prefix) {
		return "", ErrMalformedCredential
	}

	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", fmt.Errorf("%w: the Bearer token is empty", ErrMalformedCredential)
	}

	return token, nil
}
