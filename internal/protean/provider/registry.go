package provider

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Config is the stored configuration of one provider instance.
type Config struct {
	// Name is the instance name, referenced by hosts.
	Name string `json:"name"`

	// Kind selects the implementation.
	Kind string `json:"kind"`

	// Zone is the DNS zone this instance manages, for example "example.org".
	Zone string `json:"zone"`

	// Settings are implementation-specific credentials and options.
	Settings map[string]string `json:"settings"`
}

// Factory builds a Provider from a Config.
type Factory func(cfg Config) (Provider, error)

// registration is one compiled-in provider implementation.
type registration struct {
	factory Factory

	// secretKeys are the setting keys that must never be shown. Declared by
	// the implementation, because only it knows which of its settings are
	// credentials.
	secretKeys []string
}

var (
	registryMu sync.RWMutex
	registry   = map[string]registration{}
)

// Register makes an implementation available under a kind.
//
// It panics on a duplicate or malformed registration. That is correct for
// something called from init: the condition is a programming error, and the
// alternative is a binary that runs with a silently missing provider and fails
// only when an operator tries to configure it.
func Register(kind string, factory Factory, secretKeys ...string) {
	if kind == "" {
		panic("provider: Register requires a non-empty kind")
	}

	if factory == nil {
		panic("provider: Register requires a non-nil factory for kind " + kind)
	}

	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[kind]; exists {
		panic("provider: implementation " + kind + " is registered twice")
	}

	registry[kind] = registration{factory: factory, secretKeys: secretKeys}
}

// Kinds returns the compiled-in provider kinds, sorted. `provider list` shows
// this, and it is fixed at build time.
func Kinds() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	kinds := slices.Collect(maps.Keys(registry))
	sort.Strings(kinds)

	return kinds
}

// ErrUnknownKind is returned when a Config names a provider that is not
// compiled in.
var ErrUnknownKind = errors.New("provider: unknown provider")

// New builds a Provider from a Config.
func New(cfg Config) (Provider, error) {
	if cfg.Name == "" {
		return nil, errors.New("provider: a provider name is required")
	}

	if cfg.Zone == "" {
		return nil, errors.New("provider: a zone is required")
	}

	registryMu.RLock()
	reg, ok := registry[cfg.Kind]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w %q, compiled-in providers are: %s",
			ErrUnknownKind, cfg.Kind, strings.Join(Kinds(), ", "))
	}

	instance, err := reg.factory(cfg)
	if err != nil {
		return nil, fmt.Errorf("provider: configure %s provider %q: %w", cfg.Kind, cfg.Name, err)
	}

	return instance, nil
}

// Redacted returns cfg's settings with credential values replaced by "(set)",
// so `provider list` can show that a token is configured without showing it.
//
// Least-privilege credentials - a zone-scoped Cloudflare token, an IAM policy
// restricted to the hosted zone - are the operator's responsibility, but
// keeping them out of CLI output is this code's.
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

// Require returns a setting, or an error naming the missing key.
func (c Config) Require(key string) (string, error) {
	value := strings.TrimSpace(c.Settings[key])
	if value == "" {
		return "", fmt.Errorf("setting %q is required", key)
	}

	return value, nil
}
