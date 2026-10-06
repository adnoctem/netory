package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/notify"
	"github.com/adnoctem/netory/pkg/secret"
)

// notifierPrefix namespaces notifier configuration.
const notifierPrefix = "notifier/"

// Sentinel errors.
var (
	// ErrNotifierNotFound is returned when a notifier is not configured.
	ErrNotifierNotFound = errors.New("notifier not found")

	// ErrNotifierExists is returned when adding one that already exists.
	ErrNotifierExists = errors.New("notifier already exists")
)

// Notifiers persists notifier instance configuration.
//
// The credentials in these documents are why the database is encrypted: an
// SMTP password sitting in plaintext on disk would make the database file
// equivalent to the password itself.
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

	// Sorted here rather than relying on Scan, which kv.Store documents as
	// returning entries in unspecified order (§9.8).
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
