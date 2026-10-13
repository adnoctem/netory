package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/pkg/kv"
)

// tokenPrefix namespaces token records.
//
// The key is the token's hash, so the store never holds a usable token - the
// same arrangement protean uses. A Valkey snapshot therefore carries no
// credential a reader could present.
const tokenPrefix = "token/"

// DefaultTokenLifetime is how long an issued access token is valid.
//
// Ten minutes, which is the order most Admin APIs use, so a client written
// against the backend behaves the same way - and short enough that a leaked
// token is a short-lived problem. A client holding its credentials can always
// ask for another.
const DefaultTokenLifetime = 10 * time.Minute

// MaxTokenLifetime bounds the configurable lifetime.
//
// An access token is a bearer credential that travels on every request. A
// lifetime of days would make revocation theoretical: tokens are revocable
// immediately, and `token revoke` delivers that, but a token nobody
// revokes is one that works for as long as it lives.
const MaxTokenLifetime = 24 * time.Hour

// Token is an issued access token's record.
//
// There is no field holding the token: the key is its hash and that is all
// pivot keeps.
type Token struct {
	// Hash is the SHA-256 of the token, which is also its key.
	Hash string `json:"hash"`

	// ClientID is the client the token authenticates as.
	ClientID string `json:"client_id"`

	// Label is an optional note for a long-lived token issued by the CLI,
	// distinguishing "the CI pipeline's" from "the one I made to test with".
	Label string `json:"label,omitempty"`

	// Scope is the OAuth2 scope the token was issued with, echoed back on the
	// token response.
	Scope string `json:"scope,omitempty"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// IssuedBy is who issued it: the client itself for a token exchange, or
	// the socket peer for one made with `token create`.
	IssuedBy string `json:"issued_by"`
}

// Expired reports whether the token is past its expiry.
func (t Token) Expired(now time.Time) bool { return !t.ExpiresAt.After(now) }

// TTL returns how long the token has left.
func (t Token) TTL(now time.Time) time.Duration {
	if t.Expired(now) {
		return 0
	}

	return t.ExpiresAt.Sub(now)
}

// Sentinel errors.
var (
	// ErrTokenNotFound is returned for a token that does not exist, has
	// expired, or was revoked. The three are one answer on purpose: telling a
	// caller which would say whether a token ever existed.
	ErrTokenNotFound = errors.New("token not found")

	// ErrTokenLifetime is returned for a lifetime outside the allowed range.
	ErrTokenLifetime = errors.New("token lifetime out of range")
)

// Tokens persists issued access tokens.
type Tokens struct {
	store kv.Handle
	now   func() time.Time
}

// NewTokens returns the token repository.
func NewTokens(store kv.Handle, now func() time.Time) *Tokens {
	if now == nil {
		now = time.Now
	}

	return &Tokens{store: store, now: now}
}

// Issue creates a token for a client and returns the token once.
//
// The record is written with a kv TTL equal to the lifetime, so an expired
// token disappears from the store rather than accumulating. That matters more
// here than for a cache entry: tokens are issued per client per lifetime, so
// a busy instance would otherwise grow a token record every few minutes
// forever, and the expensive listing operations would get slower
// without bound.
func (t *Tokens) Issue(ctx context.Context, client, label, scope, by string, lifetime time.Duration) (string, Token, error) {
	if lifetime <= 0 {
		lifetime = DefaultTokenLifetime
	}

	if lifetime > MaxTokenLifetime {
		return "", Token{}, fmt.Errorf("%w: %s, the maximum is %s",
			ErrTokenLifetime, lifetime, MaxTokenLifetime)
	}

	value, err := auth.GenerateToken()
	if err != nil {
		return "", Token{}, err
	}

	now := t.now().UTC()

	token := Token{
		Hash:      auth.Hash(value),
		ClientID:  client,
		Label:     label,
		Scope:     scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(lifetime),
		IssuedBy:  by,
	}

	encoded, err := json.Marshal(token)
	if err != nil {
		return "", Token{}, fmt.Errorf("app: encode a token record: %w", err)
	}

	// SetIfAbsent rather than Set. A collision means 32 bytes of randomness
	// repeated, which will not happen - but if it somehow did, overwriting
	// would silently reassign one client's live token to another client.
	wrote, err := t.store.SetIfAbsent(ctx, tokenPrefix+token.Hash, encoded, kv.WithTTL(lifetime))
	if err != nil {
		return "", Token{}, fmt.Errorf("app: store a token record: %w", err)
	}

	if !wrote {
		return "", Token{}, errors.New("app: a generated token collided with an existing one")
	}

	return value, token, nil
}

// Resolve looks a token up by its value.
//
// The expiry is checked here as well as being a store TTL. kv.TTLGranularity
// makes a TTL a lower bound honoured to the second, so a token can outlive its
// expiry in the store by just under a second - and a bearer credential that
// works for a moment after it expired is not a property to leave to the
// store's rounding.
func (t *Tokens) Resolve(ctx context.Context, value string) (Token, error) {
	hash := auth.Hash(value)

	raw, err := t.store.Get(ctx, tokenPrefix+hash)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return Token{}, ErrTokenNotFound
		}

		return Token{}, fmt.Errorf("app: read a token record: %w", err)
	}

	var token Token
	if err := json.Unmarshal(raw, &token); err != nil {
		return Token{}, fmt.Errorf("app: decode a token record: %w", err)
	}

	if token.Expired(t.now()) {
		return Token{}, ErrTokenNotFound
	}

	return token, nil
}

// Revoke removes a token by its value, for a client withdrawing its own.
func (t *Tokens) Revoke(ctx context.Context, value string) error {
	return t.RevokeHash(ctx, auth.Hash(value))
}

// RevokeHash removes a token by its hash, which is what `token revoke` has:
// the operator can see hashes in `token list` and never the tokens.
func (t *Tokens) RevokeHash(ctx context.Context, hash string) error {
	if _, err := t.store.Get(ctx, tokenPrefix+hash); err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return ErrTokenNotFound
		}

		return fmt.Errorf("app: read a token record: %w", err)
	}

	if err := t.store.Delete(ctx, tokenPrefix+hash); err != nil {
		return fmt.Errorf("app: revoke a token: %w", err)
	}

	return nil
}

// RevokeForClient removes every token belonging to a client and returns how
// many went.
//
// Called by `client remove` and by a suspension: a client whose record is gone
// must not keep working through a token issued before it went.
func (t *Tokens) RevokeForClient(ctx context.Context, client string) (int, error) {
	tokens, err := t.listFor(ctx, client)
	if err != nil {
		return 0, err
	}

	removed := 0

	for _, token := range tokens {
		if err := t.store.Delete(ctx, tokenPrefix+token.Hash); err != nil {
			return removed, fmt.Errorf("app: revoke a token for %s: %w", client, err)
		}

		removed++
	}

	return removed, nil
}

// List returns every live token, newest first.
func (t *Tokens) List(ctx context.Context) ([]Token, error) {
	return t.listFor(ctx, "")
}

// ListFor returns a client's live tokens, newest first.
func (t *Tokens) ListFor(ctx context.Context, client string) ([]Token, error) {
	return t.listFor(ctx, client)
}

// listFor scans the namespace, optionally filtering by client.
//
// A scan because the key is the token's hash, which is the right key - it
// means the store holds no usable credential - and the cost is that finding a
// client's tokens cannot be a lookup. This is an administrative path, which is
// where a namespace walk belongs.
func (t *Tokens) listFor(ctx context.Context, client string) ([]Token, error) {
	now := t.now()

	var tokens []Token

	err := t.store.Scan(ctx, tokenPrefix, func(e kv.Entry) error {
		var token Token
		if err := json.Unmarshal(e.Value, &token); err != nil {
			return fmt.Errorf("app: decode the token record at %q: %w", e.Key, err)
		}

		// An expired record the store has not yet collected is not a token.
		if token.Expired(now) {
			return nil
		}

		if client != "" && token.ClientID != client {
			return nil
		}

		tokens = append(tokens, token)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("app: list tokens: %w", err)
	}

	sort.Slice(tokens, func(i, j int) bool {
		if !tokens[i].IssuedAt.Equal(tokens[j].IssuedAt) {
			return tokens[i].IssuedAt.After(tokens[j].IssuedAt)
		}

		return tokens[i].Hash < tokens[j].Hash
	})

	return tokens, nil
}
