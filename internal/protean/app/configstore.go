package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/adnoctem/netory/internal/protean/provider"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/notify"
	"github.com/adnoctem/netory/pkg/secret"
)

// Key prefixes for the two kinds of instance configuration.
const (
	providerPrefix = "provider/"
	notifierPrefix = "notifier/"
)

// Sentinel errors shared by both stores.
var (
	// ErrProviderNotFound is returned when a provider instance is not
	// configured.
	ErrProviderNotFound = errors.New("provider not found")

	// ErrProviderExists is returned when adding a provider that already
	// exists.
	ErrProviderExists = errors.New("provider already exists")

	// ErrProviderInUse is returned when removing a provider some host still
	// references.
	ErrProviderInUse = errors.New("provider is still in use")

	// ErrNotifierNotFound is returned when a notifier instance is not
	// configured.
	ErrNotifierNotFound = errors.New("notifier not found")

	// ErrNotifierExists is returned when adding a notifier that already
	// exists.
	ErrNotifierExists = errors.New("notifier already exists")
)

// Providers persists provider instance configuration.
//
// The credentials in these documents are the reason the database is encrypted:
// a Cloudflare token or an AWS secret key sitting in plaintext on disk would
// make the database file equivalent to the credentials themselves.
type Providers struct {
	store kv.Handle
}

// NewProviders returns the provider-config repository.
func NewProviders(store kv.Handle) *Providers { return &Providers{store: store} }

// Add stores a new provider instance, after checking it can actually be built.
//
// Building it first means a bad credential or a missing setting is rejected at
// `provider add`, not discovered on the first update attempt. The constructed
// instance is discarded - this only confirms the configuration is coherent.
func (p *Providers) Add(ctx context.Context, cfg provider.Config) error {
	if _, err := provider.New(cfg); err != nil {
		return err
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode provider %q: %w", cfg.Name, err)
	}

	wrote, err := p.store.SetIfAbsent(ctx, providerPrefix+cfg.Name, encoded)
	if err != nil {
		return fmt.Errorf("store provider %q: %w", cfg.Name, err)
	}

	if !wrote {
		return fmt.Errorf("%w: %s", ErrProviderExists, cfg.Name)
	}

	return nil
}

// Get returns a provider's stored configuration.
func (p *Providers) Get(ctx context.Context, name string) (provider.Config, error) {
	raw, err := p.store.Get(ctx, providerPrefix+name)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return provider.Config{}, fmt.Errorf("%w: %s", ErrProviderNotFound, name)
		}

		return provider.Config{}, fmt.Errorf("read provider %q: %w", name, err)
	}

	var cfg provider.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return provider.Config{}, fmt.Errorf("decode provider %q: %w", name, err)
	}

	return cfg, nil
}

// Build constructs a usable Provider from stored configuration.
func (p *Providers) Build(ctx context.Context, name string) (provider.Provider, error) {
	cfg, err := p.Get(ctx, name)
	if err != nil {
		return nil, err
	}

	return provider.New(cfg)
}

// List returns every provider configuration, sorted by name.
func (p *Providers) List(ctx context.Context) ([]provider.Config, error) {
	var configs []provider.Config
	err := p.store.Scan(ctx, providerPrefix, func(e kv.Entry) error {
		var cfg provider.Config
		if err := json.Unmarshal(e.Value, &cfg); err != nil {
			return fmt.Errorf("decode provider at %q: %w", e.Key, err)
		}

		configs = append(configs, cfg)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list providers: %w", err)
	}

	sort.Slice(configs, func(i, j int) bool { return configs[i].Name < configs[j].Name })

	return configs, nil
}

// Remove deletes a provider configuration, refusing while a host references it.
//
// Removing it anyway would leave hosts that accept updates and then fail to
// write them, which presents as a DNS outage rather than as the configuration
// error it is.
func (p *Providers) Remove(ctx context.Context, name string, hosts *Hosts) error {
	if _, err := p.Get(ctx, name); err != nil {
		return err
	}

	configured, err := hosts.List(ctx)
	if err != nil {
		return err
	}

	var users []string
	for _, host := range configured {
		if host.Provider == name {
			users = append(users, host.Name)
		}
	}

	if len(users) > 0 {
		return fmt.Errorf("%w by %d host(s): %v", ErrProviderInUse, len(users), users)
	}

	if err := p.store.Delete(ctx, providerPrefix+name); err != nil {
		return fmt.Errorf("remove provider %q: %w", name, err)
	}

	return nil
}

// Notifiers persists notifier instance configuration.
type Notifiers struct {
	store kv.Handle
}

// NewNotifiers returns the notifier-config repository.
func NewNotifiers(store kv.Handle) *Notifiers { return &Notifiers{store: store} }

// Add stores a new notifier instance, after checking it can be built.
func (n *Notifiers) Add(ctx context.Context, cfg notify.Config, sec *secret.Secret) error {
	// Built first, so a missing setting or an unparsable address is rejected
	// at `notifier add` rather than discovered when the first alert fails to
	// send - which is exactly when nobody is watching the log.
	if _, err := notify.New(cfg, sec); err != nil {
		return err
	}

	encoded, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode notifier %q: %w", cfg.Name, err)
	}

	wrote, err := n.store.SetIfAbsent(ctx, notifierPrefix+cfg.Name, encoded)
	if err != nil {
		return fmt.Errorf("store notifier %q: %w", cfg.Name, err)
	}

	if !wrote {
		return fmt.Errorf("%w: %s", ErrNotifierExists, cfg.Name)
	}

	return nil
}

// Get returns a notifier's stored configuration.
func (n *Notifiers) Get(ctx context.Context, name string) (notify.Config, error) {
	raw, err := n.store.Get(ctx, notifierPrefix+name)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return notify.Config{}, fmt.Errorf("%w: %s", ErrNotifierNotFound, name)
		}

		return notify.Config{}, fmt.Errorf("read notifier %q: %w", name, err)
	}

	var cfg notify.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return notify.Config{}, fmt.Errorf("decode notifier %q: %w", name, err)
	}

	return cfg, nil
}

// List returns every notifier configuration, sorted by name.
func (n *Notifiers) List(ctx context.Context) ([]notify.Config, error) {
	var configs []notify.Config
	err := n.store.Scan(ctx, notifierPrefix, func(e kv.Entry) error {
		var cfg notify.Config
		if err := json.Unmarshal(e.Value, &cfg); err != nil {
			return fmt.Errorf("decode notifier at %q: %w", e.Key, err)
		}

		configs = append(configs, cfg)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list notifiers: %w", err)
	}

	sort.Slice(configs, func(i, j int) bool { return configs[i].Name < configs[j].Name })

	return configs, nil
}

// Remove deletes a notifier configuration.
func (n *Notifiers) Remove(ctx context.Context, name string) error {
	if _, err := n.Get(ctx, name); err != nil {
		return err
	}

	if err := n.store.Delete(ctx, notifierPrefix+name); err != nil {
		return fmt.Errorf("remove notifier %q: %w", name, err)
	}

	return nil
}
