// Package provider is protean's DNS provider interface and its registry.
//
// protean owns no DNS data. Every record it touches lives in Cloudflare,
// Route53 or Spaceship, and the provider remains the source of truth, so this
// package is a translation layer and nothing more.
//
// # The interface is protean's, not a library's
//
// The interface below is deliberately narrow: A, AAAA and TXT records for
// single names, and nothing else. No zone enumeration, no record types protean
// does not manage, no provider-specific escape hatch. A third-party library -
// libdns, say - may sit *behind* it as an adapter, but never in place of it.
// That isolates protean from an upstream API change and keeps hand-written
// providers viable, which matters because the quality of available libdns
// implementations varies by provider.
//
// # Compiled in, not loaded
//
// Providers are compiled into the binary and registered at init, in the manner
// of database/sql drivers. There is no runtime plugin loading and no cgo, so
// adding a provider is a code change and a rebuild. The registry is therefore
// fixed at build time and `provider list` can state exactly what this binary
// supports.
package provider

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Record types protean manages. Anything else is out of scope: the update
// endpoint sets addresses, and TXT exists for ACME challenges and ownership
// proofs.
const (
	TypeA    = "A"
	TypeAAAA = "AAAA"
	TypeTXT  = "TXT"
)

// DefaultTTL is used when a record carries none. Short, because a dynDNS record
// exists precisely because the address changes: a long TTL would leave
// resolvers pointing at the previous address long after protean had updated it.
const DefaultTTL = 60 * time.Second

// Record is one DNS record.
type Record struct {
	// Name is relative to the zone. The empty string means the zone apex.
	Name string `json:"name"`

	// Type is A, AAAA or TXT.
	Type string `json:"type"`

	// Value is the address for A and AAAA, or the text for TXT.
	Value string `json:"value"`

	// TTL is the record's time to live. Zero means DefaultTTL.
	TTL time.Duration `json:"ttl"`
}

// Provider reads and writes records at one DNS provider.
//
// Implementations must be safe for concurrent use: several hosts can update at
// once, and nothing serialises them.
type Provider interface {
	// Name is the configured instance name, unique within protean -
	// "cloudflare-main", not "cloudflare".
	Name() string

	// Kind is the provider implementation, as registered.
	Kind() string

	// Get returns the records for one name within a zone. A name with no
	// records is an empty slice, not an error.
	Get(ctx context.Context, zone, name string) ([]Record, error)

	// Upsert creates or replaces records. It is the whole write path: protean
	// never needs "create only" or "update only", because an address update is
	// idempotent by nature.
	Upsert(ctx context.Context, zone string, records []Record) error

	// Delete removes records.
	Delete(ctx context.Context, zone string, records []Record) error

	// Redacted returns the instance's configuration with credentials removed,
	// for `provider list`.
	Redacted() map[string]string
}

// Verifier is implemented by providers that can check their own credentials
// without writing anything, backing `provider test`.
//
// It is a separate interface rather than a Provider method so that a provider
// whose API offers no cheap read-only check does not have to fake one - a
// `provider test` that always passes is worse than one that says it cannot
// check.
type Verifier interface {
	// Verify reports whether the credentials work and the zone is reachable.
	Verify(ctx context.Context, zone string) error
}

// ValidTTL normalises a record's TTL.
func (r Record) ValidTTL() time.Duration {
	if r.TTL <= 0 {
		return DefaultTTL
	}

	return r.TTL
}

// FQDN returns the record's fully-qualified name within a zone.
func (r Record) FQDN(zone string) string {
	zone = strings.TrimSuffix(zone, ".")
	if r.Name == "" || r.Name == "@" {
		return zone
	}

	return r.Name + "." + zone
}

// Validate reports whether the record is one protean can write.
//
// Addresses are checked against the record type rather than merely parsed: an
// IPv4 address in an AAAA record is accepted by some provider APIs and then
// serves a broken zone, so the mismatch is caught here where the error can
// name the problem.
func (r Record) Validate() error {
	switch r.Type {
	case TypeA, TypeAAAA, TypeTXT:
	case "":
		return errors.New("provider: record type is empty")
	default:
		return fmt.Errorf("provider: record type %q is not one of %s, %s, %s",
			r.Type, TypeA, TypeAAAA, TypeTXT)
	}

	if r.Value == "" {
		return fmt.Errorf("provider: %s record %q has an empty value", r.Type, r.Name)
	}

	switch r.Type {
	case TypeA:
		addr := net.ParseIP(r.Value)
		if addr == nil || addr.To4() == nil {
			return fmt.Errorf("provider: %q is not an IPv4 address, which an A record requires", r.Value)
		}
	case TypeAAAA:
		addr := net.ParseIP(r.Value)
		if addr == nil {
			return fmt.Errorf("provider: %q is not an IP address", r.Value)
		}

		if addr.To4() != nil {
			return fmt.Errorf(
				"provider: %q is an IPv4 address, which an AAAA record cannot hold - use an A record",
				r.Value,
			)
		}
	}

	return nil
}

// ValidateAll validates a batch, naming the offending index.
func ValidateAll(records []Record) error {
	if len(records) == 0 {
		return errors.New("provider: no records given")
	}

	for i, record := range records {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
	}

	return nil
}
