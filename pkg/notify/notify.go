// Package notify delivers events over SMTP and HTTP webhooks.
//
// A Notifier is a transport. The bus in pkg/event owns persistence, retries and
// deduplication, so a Notifier's only job is one delivery attempt: send, or
// return an error. That split is why neither transport here has a retry loop of
// its own - a transport that retried internally would fight the outbox's
// backoff and make the configured MaxAttempts a lie.
//
// # Registration
//
// Transports are compiled in and registered at init, in the manner of
// database/sql drivers. There is no runtime plugin loading and no cgo in any of
// the three services, so adding a transport is a code change and a rebuild.
//
// # Credentials
//
// A transport's configuration carries secrets - an SMTP password, a webhook
// URL that may contain a token. They are stored in the service's encrypted
// database and must never appear in `notifier list` output, which is why Config
// has a Redacted method and why the tests assert on it.
package notify

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/secret"
)

// Notifier delivers an event over one transport.
//
// It satisfies event.Sink, so a Notifier can be handed straight to the bus.
type Notifier interface {
	// Name is the configured instance name, unique within a service - "ops-mail",
	// not "smtp". It appears in logs and in `notifier list`.
	Name() string

	// Kind is the transport, as registered: "smtp" or "webhook".
	Kind() string

	// Deliver makes one attempt. Retries belong to the outbox, not here.
	Deliver(ctx context.Context, e event.Event) error

	// Redacted returns the instance's configuration with every secret
	// removed, for `notifier list`.
	Redacted() map[string]string
}

// Config is the stored configuration of one notifier instance.
type Config struct {
	// Name is the instance name.
	Name string `json:"name"`

	// Kind selects the transport.
	Kind string `json:"kind"`

	// Settings are transport-specific. Keys a transport declares as secret
	// are omitted by Redacted.
	Settings map[string]string `json:"settings"`
}

// Factory builds a Notifier from a Config.
//
// The secret is passed so a transport can derive its own keys - the webhook
// transport derives its HMAC signing key this way - rather than being handed
// raw key material. A transport that needs no derived key simply ignores it.
type Factory func(cfg Config, sec *secret.Secret) (Notifier, error)

// registration is one compiled-in transport.
type registration struct {
	factory Factory

	// secretKeys are the setting keys whose values must never be shown. They
	// are declared by the transport, because only the transport knows which of
	// its settings are credentials.
	secretKeys []string
}

var (
	registryMu sync.RWMutex
	registry   = map[string]registration{}
)

// Register makes a transport available under a kind. It panics on a duplicate
// or malformed registration, which is correct for something called from init:
// the condition is a programming error that must not produce a running binary
// with a silently missing transport.
func Register(kind string, factory Factory, secretKeys ...string) {
	if kind == "" {
		panic("notify: Register requires a non-empty kind")
	}

	if factory == nil {
		panic("notify: Register requires a non-nil factory for kind " + kind)
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[kind]; exists {
		panic("notify: transport " + kind + " is registered twice")
	}

	registry[kind] = registration{factory: factory, secretKeys: secretKeys}
}

// Kinds returns the registered transport kinds, sorted.
func Kinds() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	kinds := slices.Collect(maps.Keys(registry))
	sort.Strings(kinds)

	return kinds
}

// ErrUnknownKind is returned when a Config names a transport that is not
// compiled in.
var ErrUnknownKind = errors.New("notify: unknown transport")

// New builds a Notifier from a Config.
func New(cfg Config, sec *secret.Secret) (Notifier, error) {
	if cfg.Name == "" {
		return nil, errors.New("notify: a notifier name is required")
	}

	registryMu.RLock()
	reg, ok := registry[cfg.Kind]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w %q, compiled-in transports are: %s",
			ErrUnknownKind, cfg.Kind, strings.Join(Kinds(), ", "))
	}

	notifier, err := reg.factory(cfg, sec)
	if err != nil {
		return nil, fmt.Errorf("notify: configure %s notifier %q: %w", cfg.Kind, cfg.Name, err)
	}

	return notifier, nil
}

// Redacted returns cfg's settings with the values of its transport's declared
// secret keys replaced.
//
// A key the transport declared secret is rendered as "(set)" or omitted
// entirely when absent, so `notifier list` can show whether a password is
// configured without showing it. Reporting "(set)" rather than dropping the key
// matters: "the SMTP password is configured" and "the SMTP password was never
// set" are different diagnoses for the same symptom.
func (c Config) Redacted() map[string]string {
	registryMu.RLock()
	reg := registry[c.Kind]
	registryMu.RUnlock()

	secrets := make(map[string]struct{}, len(reg.secretKeys))
	for _, key := range reg.secretKeys {
		secrets[key] = struct{}{}
	}

	out := make(map[string]string, len(c.Settings))
	for key, value := range c.Settings {
		if _, isSecret := secrets[key]; isSecret {
			if value != "" {
				out[key] = "(set)"
			}

			continue
		}

		out[key] = value
	}

	return out
}

// Setting returns a setting value, or "".
func (c Config) Setting(key string) string { return c.Settings[key] }

// require returns a setting, or an error naming the missing key.
func (c Config) require(key string) (string, error) {
	value := strings.TrimSpace(c.Settings[key])
	if value == "" {
		return "", fmt.Errorf("setting %q is required", key)
	}

	return value, nil
}
