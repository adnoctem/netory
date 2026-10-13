package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// MaxTokenRequestBytes bounds a token-endpoint request body.
//
// A client-credentials request is a handful of short form fields. The bound
// exists because the token endpoint is the one path pivot answers itself,
// before any client is known, so it is the only place an unauthenticated
// stranger can make pivot allocate.
const MaxTokenRequestBytes = 8 << 10

// GrantClientCredentials is the only grant type pivot supports.
//
// pivot issues credentials to machines. There is no user to redirect, so no
// authorization code flow, and no refresh token: a client that can ask for a
// token at all holds the secret and can simply ask again, which makes a
// refresh token an extra long-lived credential for no gain.
const GrantClientCredentials = "client_credentials"

// ExtractCredential reads a request's frontend credentials.
//
// In oauth2 and bearer mode a request to a proxied path carries a bearer
// token; in http-basic mode it carries the client id and secret directly. The
// token endpoint itself is handled by ParseTokenRequest, not here.
func ExtractCredential(mode FrontendMode, r *http.Request) (Credential, error) {
	header := r.Header.Get("Authorization")
	if strings.TrimSpace(header) == "" {
		return Credential{}, ErrNoCredential
	}

	switch mode {
	case FrontendOAuth2, FrontendBearer:
		token, err := parseBearer(header)
		if err != nil {
			return Credential{}, err
		}

		return Credential{Kind: KindToken, Token: token}, nil

	case FrontendBasic:
		id, secret, err := parseBasic(header)
		if err != nil {
			return Credential{}, err
		}

		if id == "" || secret == "" {
			return Credential{}, fmt.Errorf(
				"%w: Basic credentials are incomplete", ErrMalformedCredential)
		}

		return Credential{Kind: KindClientSecret, ClientID: id, Secret: secret}, nil

	default:
		return Credential{}, fmt.Errorf("%w: %q", ErrUnsupportedMode, mode)
	}
}

// TokenRequest is a parsed client-credentials request.
type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	Scope        string
}

// ParseTokenRequest reads a client-credentials request from a POST to the
// token endpoint.
//
// Both credential placements are accepted, because real clients use both: RFC
// 6749 §2.3.1 says a server must support HTTP Basic and may support the body
// form, and Shopware's own clients send the body form. Rejecting either would
// break the "existing clients work unchanged" property that is the reason this
// endpoint is emulated at all.
func ParseTokenRequest(r *http.Request) (TokenRequest, error) {
	if r.Method != http.MethodPost {
		return TokenRequest{}, fmt.Errorf(
			"%w: the token endpoint takes POST, got %s", ErrMalformedCredential, r.Method)
	}

	// Bounded before parsing rather than after: ParseForm reads the whole
	// body, and this endpoint answers strangers.
	r.Body = http.MaxBytesReader(nil, r.Body, MaxTokenRequestBytes)

	if err := r.ParseForm(); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return TokenRequest{}, fmt.Errorf(
				"%w: the request body is larger than %d bytes",
				ErrMalformedCredential, MaxTokenRequestBytes)
		}

		return TokenRequest{}, fmt.Errorf("%w: %w", ErrMalformedCredential, err)
	}

	req := TokenRequest{
		GrantType: r.PostForm.Get("grant_type"),
		ClientID:  r.PostForm.Get("client_id"),
		Scope:     r.PostForm.Get("scope"),
	}
	req.ClientSecret = r.PostForm.Get("client_secret")

	// HTTP Basic wins over the body when both are present, which is RFC 6749
	// §2.3.1's ordering. Two different client ids in one request is a confused
	// client, and silently preferring one of them would make the confusion
	// somebody else's problem later.
	if header := r.Header.Get("Authorization"); strings.TrimSpace(header) != "" {
		id, secret, err := parseBasic(header)
		if err != nil {
			return TokenRequest{}, err
		}

		if req.ClientID != "" && req.ClientID != id {
			return TokenRequest{}, fmt.Errorf(
				"%w: the request carries two different client ids, one in the Authorization "+
					"header and one in the body", ErrMalformedCredential)
		}

		req.ClientID, req.ClientSecret = id, secret
	}

	if req.GrantType == "" {
		return TokenRequest{}, fmt.Errorf("%w: no grant_type", ErrMalformedCredential)
	}

	if req.ClientID == "" || req.ClientSecret == "" {
		return TokenRequest{}, fmt.Errorf("%w: no client credentials", ErrNoCredential)
	}

	return req, nil
}

// Credential renders a token request as a credential to resolve.
func (t TokenRequest) Credential() Credential {
	return Credential{Kind: KindClientSecret, ClientID: t.ClientID, Secret: t.ClientSecret}
}

// TokenResponse is the body of a successful token request.
//
// The field names and the shape are RFC 6749 §5.1's, which is also what
// Shopware returns, so a client that parsed the backend's response parses
// pivot's. ExpiresIn is seconds, as the RFC requires - a client computing an
// expiry from it must get the same answer it would have got from the backend.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// NewTokenResponse builds a response for an issued token.
func NewTokenResponse(token string, lifetime time.Duration, scope string) TokenResponse {
	return TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(lifetime.Seconds()),
		Scope:       scope,
	}
}

// WriteTokenResponse writes a successful token response.
func WriteTokenResponse(w http.ResponseWriter, response TokenResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// No-store, per RFC 6749 §5.1. A cached token response is a credential
	// sitting in an intermediary.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(response)
}

// Error is an OAuth2 error response (RFC 6749 §5.2).
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// The error codes pivot returns.
const (
	ErrorInvalidRequest       = "invalid_request"
	ErrorInvalidClient        = "invalid_client"
	ErrorUnsupportedGrantType = "unsupported_grant_type"
	ErrorInvalidGrant         = "invalid_grant"
	ErrorServerError          = "server_error"
)

// WriteError writes an OAuth2 error response.
//
// The status is the RFC's: 400 for a malformed request, 401 for bad
// credentials. An invalid_client gets a WWW-Authenticate header so a client
// library that looks for one behaves as it would against the backend.
func WriteError(w http.ResponseWriter, status int, err Error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	if err.Code == ErrorInvalidClient {
		w.Header().Set("WWW-Authenticate", `Basic realm="pivot"`)
	}

	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(err)
}

// InvalidClient is the response for credentials pivot could not resolve.
//
// The description is deliberately the same whether the client id is unknown or
// the secret is wrong. Distinguishing them tells an attacker which half of a
// guess was right, which turns one search space into two much smaller ones.
func InvalidClient() Error {
	return Error{
		Code:        ErrorInvalidClient,
		Description: "the client credentials are invalid",
	}
}

// UnsupportedGrant is the response for a grant type pivot does not implement.
func UnsupportedGrant(grant string) Error {
	return Error{
		Code: ErrorUnsupportedGrantType,
		Description: fmt.Sprintf(
			"pivot supports only the %s grant, got %q", GrantClientCredentials, grant),
	}
}

// MethodOverrideHeaders are stripped from every request.
//
// A proxy that forwarded one would let a client turn an allowed GET into a
// method the rules never evaluated - the request pivot judged and the request
// the backend ran would differ by the one thing the rules match on.
var MethodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
}

// StripMethodOverride removes every method-override header from a request.
func StripMethodOverride(r *http.Request) {
	for _, header := range MethodOverrideHeaders {
		r.Header.Del(header)
	}
}
