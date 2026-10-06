package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/notify"
	"github.com/adnoctem/netory/pkg/seal"
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

// Notifiers persists notifier instance configuration, sealed.
//
// This is where pivot differs from its siblings, and the difference is not
// cosmetic. protean and signpost store notifier configuration as plain JSON
// and rely on Badger's encryption at rest; Valkey has no equivalent, so a
// snapshot or the RDB file Valkey writes to disk would hold every SMTP
// password and webhook URL in the clear. §8 lists notifier credentials among
// the values pivot encrypts itself, and this is that.
//
// The whole configuration is sealed rather than just the fields that look like
// credentials. Which settings are secret is the transport's knowledge, not
// this package's - notify.Config.Redacted is where that lives - and a store
// that sealed only the fields it recognised would leak the next transport's
// credential by default.
type Notifiers struct {
	store  kv.Handle
	sealer *seal.Sealer
}

// NewNotifiers returns the notifier-config repository.
func NewNotifiers(store kv.Handle, sealer *seal.Sealer) *Notifiers {
	return &Notifiers{store: store, sealer: sealer}
}

// storedNotifier is the record as it sits in Valkey.
//
// The name is outside the sealed blob so `notifier list` can report what
// exists without decrypting anything, which matters on a replica whose secret
// is wrong: it can still tell an operator which notifiers are configured while
// failing to read their credentials, and that is a far more useful failure
// than an empty list.
type storedNotifier struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Sealed []byte `json:"sealed"`
}

// Add stores a new notifier instance, after checking it can be built.
func (n *Notifiers) Add(ctx context.Context, cfg notify.Config, sec *secret.Secret) error {
	// Built first, so a missing setting or an unparsable address is rejected
	// at `notifier add` rather than discovered when the first alert fails to
	// send - which is exactly when nobody is watching the log.
	if _, err := notify.New(cfg, sec); err != nil {
		return err
	}

	encoded, err := n.encode(cfg)
	if err != nil {
		return err
	}

	wrote, err := n.store.SetIfAbsent(ctx, notifierPrefix+cfg.Name, encoded)
	if err != nil {
		return fmt.Errorf("app: store notifier %q: %w", cfg.Name, err)
	}

	if !wrote {
		return fmt.Errorf("%w: %s", ErrNotifierExists, cfg.Name)
	}

	return nil
}

// encode seals a notifier configuration for storage.
func (n *Notifiers) encode(cfg notify.Config) ([]byte, error) {
	settings, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("app: encode notifier %q: %w", cfg.Name, err)
	}

	sealed, err := n.sealer.Seal(settings)
	if err != nil {
		return nil, fmt.Errorf("app: seal notifier %q: %w", cfg.Name, err)
	}

	record, err := json.Marshal(storedNotifier{Name: cfg.Name, Kind: cfg.Kind, Sealed: sealed})
	if err != nil {
		return nil, fmt.Errorf("app: encode the notifier record for %q: %w", cfg.Name, err)
	}

	return record, nil
}

// decode unseals a stored notifier configuration.
func (n *Notifiers) decode(raw []byte) (notify.Config, error) {
	var record storedNotifier
	if err := json.Unmarshal(raw, &record); err != nil {
		return notify.Config{}, fmt.Errorf("app: decode a notifier record: %w", err)
	}

	settings, err := n.sealer.OpenSealed(record.Sealed)
	if err != nil {
		return notify.Config{}, fmt.Errorf(
			"app: the credentials for notifier %q could not be decrypted: %w. "+
				"Every replica must share one PIVOT_SECRET", record.Name, err)
	}

	var cfg notify.Config
	if err := json.Unmarshal(settings, &cfg); err != nil {
		return notify.Config{}, fmt.Errorf("app: decode notifier %q: %w", record.Name, err)
	}

	return cfg, nil
}

// Get returns a notifier's stored configuration.
func (n *Notifiers) Get(ctx context.Context, name string) (notify.Config, error) {
	raw, err := n.store.Get(ctx, notifierPrefix+name)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return notify.Config{}, fmt.Errorf("%w: %s", ErrNotifierNotFound, name)
		}

		return notify.Config{}, fmt.Errorf("app: read notifier %q: %w", name, err)
	}

	return n.decode(raw)
}

// List returns every notifier configuration, sorted by name.
func (n *Notifiers) List(ctx context.Context) ([]notify.Config, error) {
	var configs []notify.Config

	err := n.store.Scan(ctx, notifierPrefix, func(e kv.Entry) error {
		cfg, err := n.decode(e.Value)
		if err != nil {
			return err
		}

		configs = append(configs, cfg)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("app: list notifiers: %w", err)
	}

	// Sorted here rather than relying on Scan, which kv.Store documents as
	// unordered - and on Valkey a SCAN genuinely has no order (§8.2).
	sort.Slice(configs, func(i, j int) bool { return configs[i].Name < configs[j].Name })

	return configs, nil
}

// Names returns the configured notifier names and kinds without decrypting
// anything.
//
// This is the call for a replica that cannot read its own credentials: it can
// still say which notifiers exist, which is a far more useful failure than an
// empty list.
func (n *Notifiers) Names(ctx context.Context) (map[string]string, error) {
	out := map[string]string{}

	err := n.store.Scan(ctx, notifierPrefix, func(e kv.Entry) error {
		var record storedNotifier
		if err := json.Unmarshal(e.Value, &record); err != nil {
			return fmt.Errorf("app: decode a notifier record at %q: %w", e.Key, err)
		}

		out[record.Name] = record.Kind

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("app: list notifier names: %w", err)
	}

	return out, nil
}

// Remove deletes a notifier configuration.
func (n *Notifiers) Remove(ctx context.Context, name string) error {
	if _, err := n.store.Get(ctx, notifierPrefix+name); err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return fmt.Errorf("%w: %s", ErrNotifierNotFound, name)
		}

		return fmt.Errorf("app: read notifier %q: %w", name, err)
	}

	if err := n.store.Delete(ctx, notifierPrefix+name); err != nil {
		return fmt.Errorf("app: remove notifier %q: %w", name, err)
	}

	return nil
}
