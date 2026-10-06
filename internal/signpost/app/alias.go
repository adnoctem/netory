package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/adnoctem/netory/pkg/kv"
)

// aliasPrefix namespaces alias records.
const aliasPrefix = "alias/"

// DefaultAlias is the alias the public routes are served from unless an
// operator configures otherwise.
const DefaultAlias = "latest"

// MaxAliasLen bounds an alias name.
const MaxAliasLen = 64

// aliasName is the character set allowed in an alias.
//
// Narrow for the same reason a release identifier is: an alias is referenced
// on a command line and recorded in events, and there is no reason for it to
// contain anything that needs quoting.
var aliasName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Alias points at one release.
//
// Publishing and rollback are atomic alias swaps (§2), which is what
// guarantees a client never observes a half-published state: the release and
// all its content exist before any alias names them, so an alias only ever
// points at something complete.
type Alias struct {
	// Name is the alias, such as "latest" or "stable".
	Name string `json:"name"`

	// Release is the release it points at.
	Release string `json:"release"`

	// Previous is what it pointed at before, which is what `bundle rollback`
	// moves back to. One step of history is enough: rollback is for undoing
	// the publish that just broke, and a chain nobody prunes would be another
	// thing to reason about.
	Previous string `json:"previous,omitempty"`

	// UpdatedAt is when it last moved, and UpdatedBy who moved it.
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// Sentinel errors.
var (
	// ErrAliasNotFound is returned when an alias is not configured.
	ErrAliasNotFound = errors.New("alias not found")

	// ErrNoPreviousRelease is returned when an alias has nothing to roll back
	// to.
	ErrNoPreviousRelease = errors.New("alias has no previous release to roll back to")

	// ErrAliasRaced is returned when an alias moved between being read and
	// being written.
	ErrAliasRaced = errors.New("alias changed concurrently")
)

// ValidateAlias reports whether a name is usable as an alias.
func ValidateAlias(name string) error {
	if name == "" {
		return errors.New("signpost: an alias name is required")
	}

	if len(name) > MaxAliasLen {
		return fmt.Errorf("signpost: alias %q is %d bytes, the limit is %d",
			name, len(name), MaxAliasLen)
	}

	if !aliasName.MatchString(name) {
		return fmt.Errorf(
			"signpost: alias %q may only contain letters, digits, '.', '_' and '-'", name)
	}

	return nil
}

// Aliases is the persistence for Alias records.
type Aliases struct {
	store kv.Handle
}

// NewAliases returns the alias repository over a namespace handle.
func NewAliases(store kv.Handle) *Aliases { return &Aliases{store: store} }

// Get returns an alias.
func (a *Aliases) Get(ctx context.Context, name string) (Alias, error) {
	raw, err := a.store.Get(ctx, aliasPrefix+name)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return Alias{}, fmt.Errorf("%w: %s", ErrAliasNotFound, name)
		}

		return Alias{}, fmt.Errorf("read alias %q: %w", name, err)
	}

	var alias Alias
	if err := json.Unmarshal(raw, &alias); err != nil {
		return Alias{}, fmt.Errorf("decode alias %q: %w", name, err)
	}

	return alias, nil
}

// Set points an alias at a release, atomically.
//
// This is the swap §2 calls atomic, and the atomicity is real rather than
// asserted. The write is a compare-and-swap against the bytes the alias held
// when it was read, so two publishes racing to move the same alias cannot
// interleave into a state neither of them intended - the loser is told the
// alias moved and can decide what to do, rather than silently overwriting a
// release it never saw.
//
// expected is the alias as previously read, or the zero Alias to create one.
func (a *Aliases) Set(ctx context.Context, expected Alias, release, by string) (Alias, error) {
	if err := ValidateAlias(expected.Name); err != nil {
		return Alias{}, err
	}

	updated := Alias{
		Name:      expected.Name,
		Release:   release,
		Previous:  expected.Release,
		UpdatedAt: time.Now().UTC(),
		UpdatedBy: by,
	}

	encoded, err := json.Marshal(updated)
	if err != nil {
		return Alias{}, fmt.Errorf("encode alias %q: %w", expected.Name, err)
	}

	key := aliasPrefix + expected.Name

	// A brand-new alias: create exclusively, so two concurrent creations
	// cannot both believe they succeeded.
	if expected.Release == "" && expected.UpdatedAt.IsZero() {
		wrote, err := a.store.SetIfAbsent(ctx, key, encoded)
		if err != nil {
			return Alias{}, fmt.Errorf("store alias %q: %w", expected.Name, err)
		}

		if !wrote {
			return Alias{}, fmt.Errorf("%w: %s was created concurrently", ErrAliasRaced, expected.Name)
		}

		return updated, nil
	}

	// An existing alias: swap only if it still holds what we read.
	current, err := json.Marshal(expected)
	if err != nil {
		return Alias{}, fmt.Errorf("encode the expected alias %q: %w", expected.Name, err)
	}

	swapped, err := a.store.CompareAndSwap(ctx, key, current, encoded)
	if err != nil {
		return Alias{}, fmt.Errorf("move alias %q: %w", expected.Name, err)
	}

	if !swapped {
		return Alias{}, fmt.Errorf(
			"%w: %s moved while this change was being prepared, so nothing was written",
			ErrAliasRaced, expected.Name)
	}

	return updated, nil
}

// List returns every alias, sorted by name.
func (a *Aliases) List(ctx context.Context) ([]Alias, error) {
	var aliases []Alias

	err := a.store.Scan(ctx, aliasPrefix, func(e kv.Entry) error {
		var alias Alias
		if err := json.Unmarshal(e.Value, &alias); err != nil {
			return fmt.Errorf("decode alias at %q: %w", e.Key, err)
		}

		aliases = append(aliases, alias)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list aliases: %w", err)
	}

	sort.Slice(aliases, func(i, j int) bool { return aliases[i].Name < aliases[j].Name })

	return aliases, nil
}

// Remove deletes an alias.
func (a *Aliases) Remove(ctx context.Context, name string) error {
	if _, err := a.Get(ctx, name); err != nil {
		return err
	}

	if err := a.store.Delete(ctx, aliasPrefix+name); err != nil {
		return fmt.Errorf("remove alias %q: %w", name, err)
	}

	return nil
}

// ReferencedBy returns the aliases pointing at a release.
//
// Used before removing one: a release an alias still names must not be
// deleted, or the alias would resolve to nothing and the routes it serves
// would vanish without anyone having asked for that.
func (a *Aliases) ReferencedBy(ctx context.Context, release string) ([]string, error) {
	aliases, err := a.List(ctx)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, alias := range aliases {
		if alias.Release == release {
			names = append(names, alias.Name)
		}
	}

	return names, nil
}
