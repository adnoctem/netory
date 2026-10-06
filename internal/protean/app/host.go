package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/adnoctem/netory/pkg/kv"
)

// hostPrefix namespaces host records within the hosts namespace.
const hostPrefix = "host/"

// MaxHostnameLen is the DNS limit on a fully-qualified name.
const MaxHostnameLen = 253

// Host is one name protean keeps updated.
type Host struct {
	// Name is the fully-qualified name, lower-cased. It is the key clients
	// authenticate as.
	Name string `json:"name"`

	// Provider is the name of the provider instance that owns this name's
	// zone.
	Provider string `json:"provider"`

	// ManageA and ManageAAAA select which address families are written.
	//
	// Both default to true, and AAAA genuinely matters: on a DS-Lite
	// connection the IPv4 address protean observes belongs to the ISP's
	// carrier-grade NAT rather than the subscriber, so IPv6 is frequently the
	// only address that is actually the client's.
	ManageA    bool `json:"manage_a"`
	ManageAAAA bool `json:"manage_aaaa"`

	// TTL overrides the provider default for this host's records.
	TTL time.Duration `json:"ttl,omitzero"`

	// LastIPv4 and LastIPv6 are the addresses last written to the provider.
	//
	// They exist to answer DynDNS2's `nochg` without a provider call: an
	// unchanged address must cost nothing downstream, and a router that
	// re-sends the same address every five minutes is the normal case rather
	// than the exception.
	LastIPv4 string `json:"last_ipv4,omitempty"`
	LastIPv6 string `json:"last_ipv6,omitempty"`

	// LastUpdateAt is when an address was last written.
	LastUpdateAt time.Time `json:"last_update_at,omitzero"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NormaliseHostname lower-cases a hostname and strips a trailing dot.
//
// DNS names are case-insensitive, so a client authenticating as
// "Dyn.Example.ORG" must reach the same host as one using "dyn.example.org".
// Normalising on the way in means the stored key is canonical and the lookup
// cannot miss on case alone.
func NormaliseHostname(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// ValidateHostname reports whether name is a plausible fully-qualified name.
//
// This is a sanity check, not a resolver: protean does not own the zone and
// cannot know whether the name exists. It rejects what would certainly break -
// an empty label, an over-long name, characters that cannot appear in a
// hostname - so that a typo fails at `host add` instead of as a provider error
// on every subsequent update.
func ValidateHostname(name string) error {
	if name == "" {
		return errors.New("hostname is empty")
	}

	if len(name) > MaxHostnameLen {
		return fmt.Errorf("hostname is %d bytes, the DNS limit is %d", len(name), MaxHostnameLen)
	}

	// A bare address is not a hostname, and accepting one would produce a
	// record that can never resolve.
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("%q is an IP address, not a hostname", name)
	}

	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q is not fully qualified, it needs at least one dot", name)
	}

	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("%q contains an empty label", name)
		}

		if len(label) > 63 {
			return fmt.Errorf("label %q is %d bytes, the DNS limit is 63", label, len(label))
		}

		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("label %q may not start or end with a hyphen", label)
		}

		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z',
				c >= '0' && c <= '9',
				c == '-', c == '_':
			default:
				return fmt.Errorf("label %q contains %q, which is not valid in a hostname", label, string(c))
			}
		}
	}

	return nil
}

// RelativeName returns the host's name relative to a zone, for the provider.
//
// A host whose name equals the zone is the apex and relativises to "", which is
// what the provider interface expects.
func (h Host) RelativeName(zone string) (string, error) {
	zone = NormaliseHostname(zone)
	name := NormaliseHostname(h.Name)

	if name == zone {
		return "", nil
	}

	suffix := "." + zone
	if !strings.HasSuffix(name, suffix) {
		return "", fmt.Errorf(
			"host %q is not inside zone %q - check that it is assigned to the right provider",
			h.Name, zone,
		)
	}

	return strings.TrimSuffix(name, suffix), nil
}

// LastAddress returns the last written address for a family.
func (h Host) LastAddress(ipv6 bool) string {
	if ipv6 {
		return h.LastIPv6
	}

	return h.LastIPv4
}

// Manages reports whether the host writes records for a family.
func (h Host) Manages(ipv6 bool) bool {
	if ipv6 {
		return h.ManageAAAA
	}

	return h.ManageA
}

// Hosts is the persistence for Host records.
type Hosts struct {
	store kv.Handle
}

// NewHosts returns the host repository over a namespace handle.
func NewHosts(store kv.Handle) *Hosts { return &Hosts{store: store} }

// ErrHostNotFound is returned when a host is not configured.
var ErrHostNotFound = errors.New("host not found")

// ErrHostExists is returned when adding a host that already exists.
var ErrHostExists = errors.New("host already exists")

// Add stores a new host, failing if it already exists.
func (h *Hosts) Add(ctx context.Context, host Host) error {
	host.Name = NormaliseHostname(host.Name)
	if err := ValidateHostname(host.Name); err != nil {
		return err
	}

	if host.Provider == "" {
		return errors.New("a provider is required")
	}

	if !host.ManageA && !host.ManageAAAA {
		return errors.New("a host must manage at least one of A and AAAA")
	}

	now := time.Now().UTC()
	host.CreatedAt, host.UpdatedAt = now, now

	encoded, err := json.Marshal(host)
	if err != nil {
		return fmt.Errorf("encode host %q: %w", host.Name, err)
	}

	// SetIfAbsent rather than Set, so `host add` on an existing name is an
	// error instead of silently resetting its provider and last-known
	// addresses.
	wrote, err := h.store.SetIfAbsent(ctx, hostPrefix+host.Name, encoded)
	if err != nil {
		return fmt.Errorf("store host %q: %w", host.Name, err)
	}

	if !wrote {
		return fmt.Errorf("%w: %s", ErrHostExists, host.Name)
	}

	return nil
}

// Get returns a host by name.
func (h *Hosts) Get(ctx context.Context, name string) (Host, error) {
	name = NormaliseHostname(name)

	raw, err := h.store.Get(ctx, hostPrefix+name)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return Host{}, fmt.Errorf("%w: %s", ErrHostNotFound, name)
		}

		return Host{}, fmt.Errorf("read host %q: %w", name, err)
	}

	var host Host
	if err := json.Unmarshal(raw, &host); err != nil {
		return Host{}, fmt.Errorf("decode host %q: %w", name, err)
	}

	return host, nil
}

// Put overwrites a host, failing if it does not already exist.
func (h *Hosts) Put(ctx context.Context, host Host) error {
	host.Name = NormaliseHostname(host.Name)

	existing, err := h.Get(ctx, host.Name)
	if err != nil {
		return err
	}

	host.CreatedAt = existing.CreatedAt
	host.UpdatedAt = time.Now().UTC()

	encoded, err := json.Marshal(host)
	if err != nil {
		return fmt.Errorf("encode host %q: %w", host.Name, err)
	}

	if err := h.store.Set(ctx, hostPrefix+host.Name, encoded); err != nil {
		return fmt.Errorf("store host %q: %w", host.Name, err)
	}

	return nil
}

// RecordUpdate persists the addresses just written to the provider.
func (h *Hosts) RecordUpdate(ctx context.Context, name, ipv4, ipv6 string) error {
	host, err := h.Get(ctx, name)
	if err != nil {
		return err
	}

	if ipv4 != "" {
		host.LastIPv4 = ipv4
	}
	if ipv6 != "" {
		host.LastIPv6 = ipv6
	}
	host.LastUpdateAt = time.Now().UTC()

	return h.Put(ctx, host)
}

// List returns every configured host, sorted by name.
func (h *Hosts) List(ctx context.Context) ([]Host, error) {
	var hosts []Host
	err := h.store.Scan(ctx, hostPrefix, func(e kv.Entry) error {
		var host Host
		if err := json.Unmarshal(e.Value, &host); err != nil {
			return fmt.Errorf("decode host at %q: %w", e.Key, err)
		}

		hosts = append(hosts, host)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}

	// kv.Store documents Scan's order as unspecified, so sorting here is
	// required rather than cosmetic.
	sortHosts(hosts)

	return hosts, nil
}

// Remove deletes a host.
func (h *Hosts) Remove(ctx context.Context, name string) error {
	name = NormaliseHostname(name)

	if _, err := h.Get(ctx, name); err != nil {
		return err
	}

	if err := h.store.Delete(ctx, hostPrefix+name); err != nil {
		return fmt.Errorf("remove host %q: %w", name, err)
	}

	return nil
}

// Exists reports whether a host is configured.
func (h *Hosts) Exists(ctx context.Context, name string) (bool, error) {
	has, err := h.store.Has(ctx, hostPrefix+NormaliseHostname(name))
	if err != nil {
		return false, fmt.Errorf("check host %q: %w", name, err)
	}

	return has, nil
}
