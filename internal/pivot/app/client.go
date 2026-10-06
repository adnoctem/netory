package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/internal/pivot/rules"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/seal"
)

// clientPrefix namespaces client records.
const clientPrefix = "client/"

// MaxClientNameLen bounds a client's label.
const MaxClientNameLen = 128

// clientName is the character set allowed in a client's label.
//
// A label appears in audit records, log lines and `client list`, so it is kept
// to characters that need no quoting and cannot forge a log line.
var clientName = regexp.MustCompile(`^[A-Za-z0-9 ._@-]+$`)

// Client is one customer of pivot.
//
// The two layers of §1 meet in this record: Rules is the first layer, and
// Backend is the credential that carries the second. Neither is sufficient
// alone, which is why both live here rather than one being derived from the
// other.
type Client struct {
	// ID is the client identifier customers authenticate with. Generated, not
	// chosen: a customer-chosen id would be guessable and would appear in
	// every audit record.
	ID string `json:"id"`

	// Name is a human label, for `client list` and the audit trail.
	Name string `json:"name"`

	// SecretHash is the SHA-256 of the client secret. The secret itself is
	// shown once at creation and cannot be recovered.
	SecretHash string `json:"secret_hash"`

	// Backend is this client's own backend credentials. §6.2 requires one set
	// per client: a customer's requests reach the backend as that customer's
	// own integration, with that integration's permissions.
	Backend auth.BackendConfig `json:"-"`

	// SealedBackend is Backend encrypted, which is how it is stored. Valkey
	// has no encryption at rest (§8), so this is pivot's own.
	SealedBackend []byte `json:"sealed_backend,omitempty"`

	// Rules are this client's additions to the global rule set (§10.2).
	// Accumulative: they can grant paths the global set does not and add
	// restrictions of their own, but cannot reopen a globally denied path.
	Rules *rules.Document `json:"rules,omitempty"`

	// RateLimit is this client's token bucket. The zero value is unlimited.
	RateLimit RateLimit `json:"rate_limit"`

	// Disabled stops the client authenticating without deleting it, so a
	// customer can be suspended and restored without reissuing credentials.
	Disabled bool `json:"disabled,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy string    `json:"created_by"`
}

// Sentinel errors.
var (
	// ErrClientNotFound is returned when a client is not configured.
	ErrClientNotFound = errors.New("client not found")

	// ErrClientExists is returned when adding a client that already exists.
	ErrClientExists = errors.New("client already exists")

	// ErrClientDisabled is returned when a disabled client authenticates.
	ErrClientDisabled = errors.New("client is disabled")
)

// ValidateClientName reports whether a label is usable.
func ValidateClientName(name string) error {
	trimmed := strings.TrimSpace(name)

	if trimmed == "" {
		return errors.New("app: a client name is required")
	}

	if len(trimmed) > MaxClientNameLen {
		return fmt.Errorf("app: client name is %d bytes, the limit is %d",
			len(trimmed), MaxClientNameLen)
	}

	if !clientName.MatchString(trimmed) {
		return fmt.Errorf(
			"app: client name %q may only contain letters, digits, spaces, '.', '_', '@' and '-'",
			name)
	}

	return nil
}

// Redacted renders a client for `client list`, with every credential removed.
func (c Client) Redacted() map[string]string {
	out := map[string]string{
		"id":         c.ID,
		"name":       c.Name,
		"rate_limit": c.RateLimit.String(),
		"created_at": c.CreatedAt.Format(time.RFC3339),
		"created_by": c.CreatedBy,
		"backend":    string(c.Backend.Mode),
		"secret":     "(set, shown once at creation)",
	}

	if c.Disabled {
		out["disabled"] = "true"
	}

	if c.Rules != nil {
		deny := len(c.Rules.Rules.Deny)
		allow := len(c.Rules.Rules.Allow)
		out["rules"] = fmt.Sprintf("%d deny, %d allow", deny, allow)
	} else {
		out["rules"] = "global only"
	}

	return out
}

// Clients persists Client records.
//
// The backend credentials in these records are why §8 lists pivot as
// encrypting values itself: Valkey offers no encryption at rest, so a Valkey
// snapshot or a RDB file on disk would otherwise hold every customer's backend
// integration credentials in the clear.
type Clients struct {
	store  kv.Handle
	sealer *seal.Sealer
}

// NewClients returns the client repository.
func NewClients(store kv.Handle, sealer *seal.Sealer) *Clients {
	return &Clients{store: store, sealer: sealer}
}

// Create stores a new client and returns it with its generated secret.
//
// The secret is returned once and never again: only its hash is stored, so a
// lost secret is reissued rather than recovered. That is the same contract
// protean's tokens have, and for the same reason - a store that can return a
// credential is a store whose compromise hands over every credential.
func (c *Clients) Create(ctx context.Context, client Client) (Client, string, error) {
	if err := ValidateClientName(client.Name); err != nil {
		return Client{}, "", err
	}

	if err := client.Backend.Validate(); err != nil {
		return Client{}, "", err
	}

	if err := client.RateLimit.Validate(); err != nil {
		return Client{}, "", err
	}

	if client.Rules != nil {
		// Compiled to validate, and the result discarded: a client record
		// holding rules that do not compile would fail at the next rule
		// reload, which is a request-path failure for a mistake made at
		// `client add`.
		if _, err := rules.Compile(*client.Rules, rules.ScopeClient); err != nil {
			return Client{}, "", fmt.Errorf("app: the client's rules do not compile: %w", err)
		}
	}

	id, err := auth.GenerateClientID()
	if err != nil {
		return Client{}, "", err
	}

	secret, err := auth.GenerateSecret()
	if err != nil {
		return Client{}, "", err
	}

	now := time.Now().UTC()

	client.ID = id
	client.SecretHash = auth.Hash(secret)
	client.Name = strings.TrimSpace(client.Name)
	client.CreatedAt = now
	client.UpdatedAt = now

	if err := c.put(ctx, client, true); err != nil {
		return Client{}, "", err
	}

	return client, secret, nil
}

// put stores a client, sealing its backend credentials.
func (c *Clients) put(ctx context.Context, client Client, exclusive bool) error {
	credentials, err := json.Marshal(client.Backend)
	if err != nil {
		return fmt.Errorf("app: encode the backend credentials for %s: %w", client.ID, err)
	}

	sealed, err := c.sealer.Seal(credentials)
	if err != nil {
		return fmt.Errorf("app: seal the backend credentials for %s: %w", client.ID, err)
	}

	client.SealedBackend = sealed

	encoded, err := json.Marshal(client)
	if err != nil {
		return fmt.Errorf("app: encode client %s: %w", client.ID, err)
	}

	if exclusive {
		wrote, err := c.store.SetIfAbsent(ctx, clientPrefix+client.ID, encoded)
		if err != nil {
			return fmt.Errorf("app: store client %s: %w", client.ID, err)
		}

		if !wrote {
			return fmt.Errorf("%w: %s", ErrClientExists, client.ID)
		}

		return nil
	}

	if err := c.store.Set(ctx, clientPrefix+client.ID, encoded); err != nil {
		return fmt.Errorf("app: store client %s: %w", client.ID, err)
	}

	return nil
}

// Get returns a client, with its backend credentials decrypted.
func (c *Clients) Get(ctx context.Context, id string) (Client, error) {
	raw, err := c.store.Get(ctx, clientPrefix+id)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return Client{}, fmt.Errorf("%w: %s", ErrClientNotFound, id)
		}

		return Client{}, fmt.Errorf("app: read client %s: %w", id, err)
	}

	return c.decode(raw, id)
}

// decode reads a stored client and unseals its credentials.
func (c *Clients) decode(raw []byte, id string) (Client, error) {
	var client Client
	if err := json.Unmarshal(raw, &client); err != nil {
		return Client{}, fmt.Errorf("app: decode client %s: %w", id, err)
	}

	if len(client.SealedBackend) == 0 {
		return client, nil
	}

	// OpenSealed rather than Open: these are credentials, so "it was stored
	// in the clear" must be an error rather than something to notice later.
	credentials, err := c.sealer.OpenSealed(client.SealedBackend)
	if err != nil {
		return Client{}, fmt.Errorf(
			"app: the backend credentials for %s could not be decrypted: %w. "+
				"Every replica must share one PIVOT_SECRET", client.ID, err)
	}

	if err := json.Unmarshal(credentials, &client.Backend); err != nil {
		return Client{}, fmt.Errorf("app: decode the backend credentials for %s: %w", client.ID, err)
	}

	return client, nil
}

// Update replaces a client's mutable fields.
func (c *Clients) Update(ctx context.Context, client Client) error {
	existing, err := c.Get(ctx, client.ID)
	if err != nil {
		return err
	}

	if err := ValidateClientName(client.Name); err != nil {
		return err
	}

	if err := client.Backend.Validate(); err != nil {
		return err
	}

	if err := client.RateLimit.Validate(); err != nil {
		return err
	}

	if client.Rules != nil {
		if _, err := rules.Compile(*client.Rules, rules.ScopeClient); err != nil {
			return fmt.Errorf("app: the client's rules do not compile: %w", err)
		}
	}

	// The secret hash and the creation record are not updatable through this
	// path: a secret changes through Rotate, and a creation time that could be
	// rewritten would be an audit trail that could be rewritten.
	client.SecretHash = existing.SecretHash
	client.CreatedAt = existing.CreatedAt
	client.CreatedBy = existing.CreatedBy
	client.UpdatedAt = time.Now().UTC()

	return c.put(ctx, client, false)
}

// RotateSecret issues a new secret for a client and returns it.
//
// The old secret stops working immediately. Any access tokens already issued
// under it keep working until they expire, which is the honest behaviour: a
// token is a separate credential with its own lifetime, and `token revoke` is
// how one is withdrawn early.
func (c *Clients) RotateSecret(ctx context.Context, id string) (string, error) {
	client, err := c.Get(ctx, id)
	if err != nil {
		return "", err
	}

	secret, err := auth.GenerateSecret()
	if err != nil {
		return "", err
	}

	client.SecretHash = auth.Hash(secret)
	client.UpdatedAt = time.Now().UTC()

	if err := c.put(ctx, client, false); err != nil {
		return "", err
	}

	return secret, nil
}

// SetDisabled suspends or restores a client.
func (c *Clients) SetDisabled(ctx context.Context, id string, disabled bool) error {
	client, err := c.Get(ctx, id)
	if err != nil {
		return err
	}

	client.Disabled = disabled
	client.UpdatedAt = time.Now().UTC()

	return c.put(ctx, client, false)
}

// List returns every client, sorted by name then id.
//
// Sorted here rather than relying on the store, which documents Scan's order
// as unspecified (§8.2) - and on Valkey a SCAN genuinely has none.
func (c *Clients) List(ctx context.Context) ([]Client, error) {
	var clients []Client

	err := c.store.Scan(ctx, clientPrefix, func(e kv.Entry) error {
		client, err := c.decode(e.Value, e.Key)
		if err != nil {
			return err
		}

		clients = append(clients, client)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("app: list clients: %w", err)
	}

	sort.Slice(clients, func(i, j int) bool {
		if clients[i].Name != clients[j].Name {
			return clients[i].Name < clients[j].Name
		}

		return clients[i].ID < clients[j].ID
	})

	return clients, nil
}

// Remove deletes a client.
func (c *Clients) Remove(ctx context.Context, id string) error {
	if _, err := c.Get(ctx, id); err != nil {
		return err
	}

	if err := c.store.Delete(ctx, clientPrefix+id); err != nil {
		return fmt.Errorf("app: remove client %s: %w", id, err)
	}

	return nil
}

// Authenticate resolves a client id and secret.
//
// The error is deliberately the same shape whether the client is unknown or
// the secret is wrong - see auth.InvalidClient for why. A disabled client is
// distinguished internally so the audit record can say so, and externally it
// is the same answer.
func (c *Clients) Authenticate(ctx context.Context, id, secret string) (Client, error) {
	client, err := c.Get(ctx, id)
	if err != nil {
		return Client{}, err
	}

	if !auth.Equal(client.SecretHash, auth.Hash(secret)) {
		return Client{}, fmt.Errorf("%w: %s", ErrClientNotFound, id)
	}

	if client.Disabled {
		return Client{}, fmt.Errorf("%w: %s", ErrClientDisabled, id)
	}

	return client, nil
}
