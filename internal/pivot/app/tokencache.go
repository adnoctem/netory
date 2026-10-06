package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/pkg/kv"
)

// backendTokenPrefix namespaces cached backend tokens.
const backendTokenPrefix = "backend-token/"

// backendTokenCache shares backend access tokens between replicas.
//
// This is the auth.TokenCache the oauth2 backend mode asks for, and sharing it
// is not an optimisation. §6.2 says the token manager shares tokens across
// replicas through Valkey, and the reason is that some backends - Shopware
// among them - issue a token that invalidates the previous one. Replicas each
// fetching their own would therefore revoke each other's, and a deployment
// would get steadily worse as it scaled out.
//
// The tokens are sealed. A backend access token is a credential: §8 lists it
// among the values pivot encrypts itself, and a Valkey snapshot holding one in
// the clear would be a working credential for the backend.
type backendTokenCache struct {
	state *State
}

// tokenCache returns the shared backend token cache.
func (s *State) tokenCache() auth.TokenCache { return &backendTokenCache{state: s} }

// storedToken is a cached backend token.
type storedToken struct {
	Token  string    `json:"token"`
	Expiry time.Time `json:"expiry"`
}

// Get returns a cached backend token.
func (c *backendTokenCache) Get(
	ctx context.Context, clientID string,
) (string, time.Time, bool, error) {
	handle, err := kv.In(c.state.Store, NamespaceConfig)
	if err != nil {
		return "", time.Time{}, false, err
	}

	raw, err := handle.Get(ctx, backendTokenPrefix+clientID)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return "", time.Time{}, false, nil
		}

		return "", time.Time{}, false, fmt.Errorf("app: read a backend token: %w", err)
	}

	plaintext, err := c.state.credentialSealer().OpenSealed(raw)
	if err != nil {
		// Reported as a miss rather than an error: pivot can fetch its own
		// token, so a wrong secret or a corrupt value costs a token request
		// rather than a failed customer request. The log line is what makes
		// the cause visible.
		c.state.Log.Warn("could not decrypt a cached backend token; fetching a fresh one",
			"client", clientID, "error", err)

		return "", time.Time{}, false, nil
	}

	var stored storedToken
	if err := json.Unmarshal(plaintext, &stored); err != nil {
		return "", time.Time{}, false, nil //nolint:nilerr // a bad record is a miss
	}

	return stored.Token, stored.Expiry, true, nil
}

// Put stores a backend token until its expiry.
func (c *backendTokenCache) Put(
	ctx context.Context, clientID, token string, expiry time.Time,
) error {
	handle, err := kv.In(c.state.Store, NamespaceConfig)
	if err != nil {
		return err
	}

	encoded, err := json.Marshal(storedToken{Token: token, Expiry: expiry})
	if err != nil {
		return fmt.Errorf("app: encode a backend token: %w", err)
	}

	sealed, err := c.state.credentialSealer().Seal(encoded)
	if err != nil {
		return fmt.Errorf("app: seal a backend token: %w", err)
	}

	// The kv TTL matches the token's own lifetime, so an expired token
	// disappears rather than accumulating one dead record per client per
	// rotation.
	ttl := time.Until(expiry)
	if ttl <= 0 {
		return nil
	}

	if err := handle.Set(ctx, backendTokenPrefix+clientID, sealed, kv.WithTTL(ttl)); err != nil {
		return fmt.Errorf("app: store a backend token: %w", err)
	}

	return nil
}
