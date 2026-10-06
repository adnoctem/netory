package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/log"
)

// TokenBytes is the size of a generated token.
//
// 32 random bytes is 256 bits. That is why no slow password hash is used to
// store these: Argon2 and bcrypt exist to make a dictionary search over
// human-chosen secrets expensive, and there is no dictionary for a full-entropy
// random value. SHA-256 is sufficient and keeps the hot path cheap, which
// matters because every update request performs one.
const TokenBytes = 32

// tokenPrefix namespaces token records. The key is the token's hash, so
// authenticating a presented token is a single point lookup rather than a scan.
const tokenPrefix = "token/"

// Token is a stored credential. The token value itself is not here: only its
// hash, and the hash is the key.
type Token struct {
	// ID is a short, non-secret handle for the token, used by `token revoke`
	// so an operator never has to paste the secret back in to manage it.
	ID string `json:"id"`

	// Host is the single name this token may update. One token belongs to one
	// host; a host may have several tokens, which is what makes rotation
	// possible without downtime.
	Host string `json:"host"`

	// Label is an operator note - "fritzbox", "ddclient on the NAS".
	Label string `json:"label,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

// HashToken returns the storage hash of a token value.
func HashToken(value string) string {
	sum := sha256.Sum256([]byte(value))

	return hex.EncodeToString(sum[:])
}

// GenerateToken returns a new random token value.
//
// Raw URL base64 so the value survives a shell, an environment variable and a
// URL without quoting - a dynDNS client configuration is frequently a URL with
// the token in it.
func GenerateToken() (string, error) {
	buf := make([]byte, TokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// generateTokenID returns a short non-secret identifier.
func generateTokenID() (string, error) {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token id: %w", err)
	}

	return hex.EncodeToString(buf), nil
}

// Tokens is the persistence for Token records.
type Tokens struct {
	store  kv.Handle
	logger *log.Logger
}

// NewTokens returns the token repository over a namespace handle.
//
// The logger reports a token record that cannot be decoded. The revocation
// paths below step over such a record rather than failing, because revoking a
// token is incident response and must not be blocked by unrelated corruption -
// so the log is the only place an unaccountable credential can surface.
func NewTokens(store kv.Handle, logger *log.Logger) *Tokens {
	if logger == nil {
		logger = log.Default()
	}

	return &Tokens{store: store, logger: logger.With(slog.String("component", "tokens"))}
}

// Sentinel errors for token operations.
var (
	// ErrTokenNotFound is returned when no token matches.
	ErrTokenNotFound = errors.New("token not found")

	// ErrTokenMismatch is returned when a token exists but belongs to a
	// different host.
	ErrTokenMismatch = errors.New("token does not belong to that host")
)

// Create issues a new token for a host and returns the value, which is the only
// time it is ever available.
func (t *Tokens) Create(ctx context.Context, host, label string) (value string, token Token, err error) {
	host = NormaliseHostname(host)
	if host == "" {
		return "", Token{}, errors.New("a host is required")
	}

	value, err = GenerateToken()
	if err != nil {
		return "", Token{}, err
	}

	id, err := generateTokenID()
	if err != nil {
		return "", Token{}, err
	}

	token = Token{
		ID:        id,
		Host:      host,
		Label:     strings.TrimSpace(label),
		CreatedAt: time.Now().UTC(),
	}

	encoded, err := json.Marshal(token)
	if err != nil {
		return "", Token{}, fmt.Errorf("encode token: %w", err)
	}

	wrote, err := t.store.SetIfAbsent(ctx, tokenPrefix+HashToken(value), encoded)
	if err != nil {
		return "", Token{}, fmt.Errorf("store token: %w", err)
	}

	// A collision here would mean crypto/rand produced the same 32 bytes
	// twice, so this is unreachable rather than a case to handle gracefully -
	// but writing the token anyway would silently reassign an existing
	// credential to a different host.
	if !wrote {
		return "", Token{}, errors.New("token hash collision, which should be impossible - try again")
	}

	return value, token, nil
}

// Authenticate resolves a presented token to its record.
//
// The token alone is the credential, and it identifies the host: a token
// belongs to exactly one host, so looking it up by hash yields the host it may
// update. No claimed hostname is required.
//
// That matters for real clients. A FRITZ!Box has separate Username, Password
// and "Domain name" fields and authenticates with HTTP Basic using the first
// two, so the username it sends is whatever the operator typed - not the
// hostname. Requiring username == hostname, as DynDNS2 conventionally implies,
// would mean an operator had to type the full hostname into a field labelled
// "Username" and would otherwise get badauth with no explanation.
//
// Use AuthenticateFor when a hostname *was* claimed and must be checked.
func (t *Tokens) Authenticate(ctx context.Context, value string) (Token, error) {
	if value == "" {
		return Token{}, ErrTokenNotFound
	}

	raw, err := t.store.Get(ctx, tokenPrefix+HashToken(value))
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return Token{}, ErrTokenNotFound
		}

		return Token{}, fmt.Errorf("read token: %w", err)
	}

	var token Token
	if err := json.Unmarshal(raw, &token); err != nil {
		return Token{}, fmt.Errorf("decode token: %w", err)
	}

	return token, nil
}

// AuthenticateFor resolves a presented token and confirms it belongs to the
// claimed host.
//
// The lookup is by hash, so the presented value is never compared against a
// stored secret directly. The constant-time comparison guards the second step -
// confirming the record's host matches the one claimed - because a timing
// difference there would let someone holding a valid token for one host
// discover other configured hostnames.
//
// Loosening the username requirement does not weaken this: the token is the
// only secret, and it can only ever update its own host. A hostname is a public
// DNS name, so requiring it to be presented correctly was never a second
// factor - it only ever turned a correct credential into an unexplained
// failure.
func (t *Tokens) AuthenticateFor(ctx context.Context, host, value string) (Token, error) {
	token, err := t.Authenticate(ctx, value)
	if err != nil {
		return Token{}, err
	}

	host = NormaliseHostname(host)
	if subtle.ConstantTimeCompare([]byte(token.Host), []byte(host)) != 1 {
		return Token{}, ErrTokenMismatch
	}

	return token, nil
}

// List returns every token, or only one host's when host is non-empty. The
// token values are not recoverable, by construction.
func (t *Tokens) List(ctx context.Context, host string) ([]Token, error) {
	host = NormaliseHostname(host)

	var tokens []Token
	err := t.store.Scan(ctx, tokenPrefix, func(e kv.Entry) error {
		var token Token
		if err := json.Unmarshal(e.Value, &token); err != nil {
			return fmt.Errorf("decode token at %q: %w", e.Key, err)
		}

		if host != "" && token.Host != host {
			return nil
		}

		tokens = append(tokens, token)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list tokens: %w", err)
	}

	sortTokens(tokens)

	return tokens, nil
}

// Revoke removes a token by its ID. It takes effect immediately, because
// authentication is a store lookup on every request with nothing cached.
//
// Finding the token requires a scan, since the store is keyed by hash and an
// operator holds only the ID. That is the right trade: authentication is the
// hot path and must be a point lookup, while revocation happens by hand.
func (t *Tokens) Revoke(ctx context.Context, id string) (Token, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Token{}, errors.New("a token ID is required")
	}

	var (
		found    Token
		foundKey string
	)
	err := t.store.Scan(ctx, tokenPrefix, func(e kv.Entry) error {
		var token Token
		if decodeErr := json.Unmarshal(e.Value, &token); decodeErr != nil {
			//nolint:nilerr // revocation must not be blocked by an unrelated bad record
			t.logger.Error("skipping an undecodable token record", "key", e.Key, "error", decodeErr)

			return nil
		}

		if token.ID == id {
			found, foundKey = token, e.Key

			return kv.ErrStopIteration
		}

		return nil
	})
	if err != nil {
		return Token{}, fmt.Errorf("find token %q: %w", id, err)
	}

	if foundKey == "" {
		return Token{}, fmt.Errorf("%w: %s", ErrTokenNotFound, id)
	}

	if err := t.store.Delete(ctx, foundKey); err != nil {
		return Token{}, fmt.Errorf("revoke token %q: %w", id, err)
	}

	return found, nil
}

// RevokeAllFor removes every token belonging to a host, and reports how many.
// Used when a host is removed, so its credentials do not outlive it.
func (t *Tokens) RevokeAllFor(ctx context.Context, host string) (int, error) {
	host = NormaliseHostname(host)

	var keys []string
	err := t.store.Scan(ctx, tokenPrefix, func(e kv.Entry) error {
		var token Token
		if decodeErr := json.Unmarshal(e.Value, &token); decodeErr != nil {
			//nolint:nilerr // as in Revoke: a bad record must not strand a host's other tokens
			t.logger.Error("skipping an undecodable token record", "key", e.Key, "error", decodeErr)

			return nil
		}

		if token.Host == host {
			keys = append(keys, e.Key)
		}

		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("find tokens for %q: %w", host, err)
	}

	for _, key := range keys {
		if err := t.store.Delete(ctx, key); err != nil {
			return 0, fmt.Errorf("revoke token for %q: %w", host, err)
		}
	}

	return len(keys), nil
}

// Rotate issues a new token for the same host and revokes the old one.
//
// The new token is created before the old is revoked, so a failure between the
// two leaves the host with two working tokens rather than none. A locked-out
// router is the worse outcome: it stops updating and nobody notices until the
// address changes.
func (t *Tokens) Rotate(ctx context.Context, id, label string) (value string, token Token, err error) {
	existing, err := t.find(ctx, id)
	if err != nil {
		return "", Token{}, err
	}

	if label == "" {
		label = existing.Label
	}

	value, token, err = t.Create(ctx, existing.Host, label)
	if err != nil {
		return "", Token{}, err
	}

	if _, err := t.Revoke(ctx, id); err != nil {
		return "", Token{}, fmt.Errorf(
			"issued the replacement token %s but could not revoke the old one %s: %w", token.ID, id, err)
	}

	return value, token, nil
}

// find locates a token by ID without removing it.
func (t *Tokens) find(ctx context.Context, id string) (Token, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Token{}, errors.New("a token ID is required")
	}

	var (
		found Token
		ok    bool
	)
	err := t.store.Scan(ctx, tokenPrefix, func(e kv.Entry) error {
		var token Token
		if decodeErr := json.Unmarshal(e.Value, &token); decodeErr != nil {
			//nolint:nilerr // as in Revoke
			t.logger.Error("skipping an undecodable token record", "key", e.Key, "error", decodeErr)

			return nil
		}

		if token.ID == id {
			found, ok = token, true

			return kv.ErrStopIteration
		}

		return nil
	})
	if err != nil {
		return Token{}, fmt.Errorf("find token %q: %w", id, err)
	}

	if !ok {
		return Token{}, fmt.Errorf("%w: %s", ErrTokenNotFound, id)
	}

	return found, nil
}
