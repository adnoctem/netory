package provider

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/libdns/libdns"
)

// libdnsClient is the subset of libdns protean actually uses.
//
// Declaring it here rather than depending on libdns's own interfaces is the
// point of the adapter: protean's provider.Provider is the contract, and this
// is the narrowest shape a libdns implementation must satisfy to serve it. A
// libdns release that adds methods, or changes ones protean does not call,
// cannot break this.
type libdnsClient interface {
	GetRecords(ctx context.Context, zone string) ([]libdns.Record, error)
	SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error)
	DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error)
}

// libdnsAdapter wraps a libdns implementation behind provider.Provider.
//
// Every libdns-backed provider shares this, so the translation between
// protean's Record and libdns's Record lives in exactly one place and the
// per-provider files are nothing but credential handling and registration.
type libdnsAdapter struct {
	name     string
	kind     string
	zone     string
	client   libdnsClient
	redacted map[string]string
}

// enforce implementation of the interface
var _ Provider = (*libdnsAdapter)(nil)

func (a *libdnsAdapter) Name() string { return a.name }
func (a *libdnsAdapter) Kind() string { return a.kind }

// Redacted implements Provider.
func (a *libdnsAdapter) Redacted() map[string]string {
	out := make(map[string]string, len(a.redacted)+1)
	for key, value := range a.redacted {
		out[key] = value
	}
	out["zone"] = a.zone

	return out
}

// Get implements Provider.
//
// libdns offers no per-name read - RecordGetter.GetRecords returns the whole
// zone - so this fetches everything and filters. That is acceptable because
// Get is not on protean's hot path: an update decides whether anything changed
// from the address stored on the host record, so a routine `nochg` costs no
// provider call at all. Get serves `provider test` and reconciliation, where a
// full zone read is fine.
func (a *libdnsAdapter) Get(ctx context.Context, zone, name string) ([]Record, error) {
	zone = a.resolveZone(zone)

	found, err := a.client.GetRecords(ctx, fqdnZone(zone))
	if err != nil {
		return nil, fmt.Errorf("provider %q: read zone %q: %w", a.name, zone, err)
	}

	want := libdnsName(name)

	var records []Record
	for _, record := range found {
		rr := record.RR()

		if !strings.EqualFold(rr.Name, want) {
			continue
		}

		// Only the types protean manages. A zone legitimately holds MX, NS and
		// everything else; surfacing them would invite a caller to try to
		// write one back through an interface that cannot express it.
		switch strings.ToUpper(rr.Type) {
		case TypeA, TypeAAAA, TypeTXT:
		default:
			continue
		}

		records = append(records, Record{
			Name:  proteanName(rr.Name),
			Type:  strings.ToUpper(rr.Type),
			Value: rr.Data,
			TTL:   rr.TTL,
		})
	}

	return records, nil
}

// Upsert implements Provider.
//
// SetRecords is exactly the semantics wanted: for each (name, type) pair in the
// input, the records given become the only members of that RRset. An address
// update is replace-in-place, not append - AppendRecords would leave the
// previous address in the zone alongside the new one, so the name would resolve
// to both and half the traffic would go nowhere.
func (a *libdnsAdapter) Upsert(ctx context.Context, zone string, records []Record) error {
	if err := ValidateAll(records); err != nil {
		return fmt.Errorf("provider %q: %w", a.name, err)
	}

	zone = a.resolveZone(zone)

	converted, err := toLibdns(records)
	if err != nil {
		return fmt.Errorf("provider %q: %w", a.name, err)
	}

	if _, err := a.client.SetRecords(ctx, fqdnZone(zone), converted); err != nil {
		return fmt.Errorf("provider %q: write %d record(s) to zone %q: %w", a.name, len(records), zone, err)
	}

	return nil
}

// Delete implements Provider.
func (a *libdnsAdapter) Delete(ctx context.Context, zone string, records []Record) error {
	if len(records) == 0 {
		return fmt.Errorf("provider %q: no records given", a.name)
	}

	zone = a.resolveZone(zone)

	converted, err := toLibdns(records)
	if err != nil {
		return fmt.Errorf("provider %q: %w", a.name, err)
	}

	if _, err := a.client.DeleteRecords(ctx, fqdnZone(zone), converted); err != nil {
		return fmt.Errorf("provider %q: delete %d record(s) from zone %q: %w", a.name, len(records), zone, err)
	}

	return nil
}

// Verify implements Verifier by reading the zone, which checks the credentials
// and the zone's reachability without writing anything.
func (a *libdnsAdapter) Verify(ctx context.Context, zone string) error {
	zone = a.resolveZone(zone)

	if _, err := a.client.GetRecords(ctx, fqdnZone(zone)); err != nil {
		return fmt.Errorf("provider %q: could not read zone %q: %w", a.name, zone, err)
	}

	return nil
}

// resolveZone falls back to the instance's configured zone when the caller
// passes none, which is the normal case - a provider instance manages one zone.
func (a *libdnsAdapter) resolveZone(zone string) string {
	if zone == "" {
		return a.zone
	}

	return zone
}

// fqdnZone renders a zone the way libdns documents zone inputs: fully
// qualified, with a trailing dot.
//
// libdns.AbsoluteName is not used for this. With an empty name it returns the
// zone verbatim, so it would silently pass "example.org" through unchanged -
// which looks like normalisation and is not. Different libdns providers are
// more or less tolerant of a missing trailing dot, so the normalisation is
// done here rather than left to each of them.
func fqdnZone(zone string) string {
	zone = strings.TrimSpace(zone)
	if zone == "" || strings.HasSuffix(zone, ".") {
		return zone
	}

	return zone + "."
}

// libdnsName converts protean's relative name to libdns's convention.
//
// libdns represents the zone apex as "@" and documents the empty string as
// invalid; protean's Record uses "" for the apex. Getting this backwards would
// send a record for "example.org" to the name ".example.org", so the mapping is
// explicit in both directions rather than incidental.
func libdnsName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "@" {
		return "@"
	}

	return name
}

// proteanName converts libdns's convention back to protean's.
func proteanName(name string) string {
	if name == "@" {
		return ""
	}

	return name
}

// toLibdns converts protean records to libdns records.
//
// A and AAAA become libdns.Address and TXT becomes libdns.TXT, rather than all
// three becoming an opaque libdns.RR. libdns documents that implementations
// should receive the typed structs, and some providers parse them differently
// from a raw RR - Route53 in particular.
func toLibdns(records []Record) ([]libdns.Record, error) {
	out := make([]libdns.Record, 0, len(records))

	for _, record := range records {
		name := libdnsName(record.Name)
		ttl := record.ValidTTL()

		switch record.Type {
		case TypeA, TypeAAAA:
			addr, err := netip.ParseAddr(record.Value)
			if err != nil {
				return nil, fmt.Errorf("%s record %q: %q is not an IP address", record.Type, record.Name, record.Value)
			}

			// Unmap, so an IPv4-mapped IPv6 value does not become an AAAA
			// record holding an IPv4 address.
			out = append(out, libdns.Address{Name: name, TTL: ttl, IP: addr.Unmap()})
		case TypeTXT:
			out = append(out, libdns.TXT{Name: name, TTL: ttl, Text: record.Value})
		default:
			return nil, fmt.Errorf("record type %q cannot be written", record.Type)
		}
	}

	return out, nil
}
