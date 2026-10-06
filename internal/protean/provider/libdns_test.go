package provider_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/protean/provider"
)

// fakeLibdns records what the adapter asked it to do and returns canned
// records. A real HTTP double would test libdns/cloudflare rather than the
// adapter, which is the thing this repository owns.
type fakeLibdns struct {
	zone string

	existing []libdns.Record
	getErr   error
	setErr   error
	delErr   error

	getCalls int
	set      []libdns.Record
	deleted  []libdns.Record
	setZone  string
}

func (f *fakeLibdns) GetRecords(_ context.Context, zone string) ([]libdns.Record, error) {
	f.getCalls++
	f.zone = zone

	return f.existing, f.getErr
}

func (f *fakeLibdns) SetRecords(_ context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	f.setZone = zone
	f.set = append(f.set, records...)

	return records, f.setErr
}

func (f *fakeLibdns) DeleteRecords(_ context.Context, _ string, records []libdns.Record) ([]libdns.Record, error) {
	f.deleted = append(f.deleted, records...)

	return records, f.delErr
}

func TestLibdnsAdapterGetFiltersByNameAndType(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := &fakeLibdns{existing: []libdns.Record{
		libdns.Address{Name: "dyn", TTL: time.Minute, IP: netip.MustParseAddr("203.0.113.1")},
		libdns.Address{Name: "dyn", TTL: time.Minute, IP: netip.MustParseAddr("2001:db8::1")},
		libdns.Address{Name: "other", TTL: time.Minute, IP: netip.MustParseAddr("203.0.113.9")},
		libdns.TXT{Name: "dyn", TTL: time.Minute, Text: "hello"},

		// A type protean does not manage must not be surfaced: doing so would
		// invite a caller to write one back through an interface that cannot
		// express it.
		libdns.MX{Name: "dyn", TTL: time.Minute, Preference: 10, Target: "mail.example.org."},
	}}

	p := provider.NewLibdnsAdapterForTest("fake", "example.org", fake)

	records, err := p.Get(ctx, "", "dyn")
	require.NoError(t, err)

	asrt.Len(records, 3, "only the A, AAAA and TXT records for that name")

	byType := map[string]provider.Record{}
	for _, record := range records {
		byType[record.Type] = record
	}

	asrt.Equal("203.0.113.1", byType[provider.TypeA].Value)
	asrt.Equal("2001:db8::1", byType[provider.TypeAAAA].Value)
	asrt.Equal("hello", byType[provider.TypeTXT].Value)
	asrt.Equal("dyn", byType[provider.TypeA].Name)
	asrt.Equal(time.Minute, byType[provider.TypeA].TTL)
}

// libdns represents the zone apex as "@" and documents the empty string as
// invalid; protean's Record uses "". Getting this backwards sends a record for
// "example.org" to the name ".example.org".
func TestLibdnsAdapterMapsTheApexName(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := &fakeLibdns{existing: []libdns.Record{
		libdns.Address{Name: "@", TTL: time.Minute, IP: netip.MustParseAddr("203.0.113.1")},
	}}

	p := provider.NewLibdnsAdapterForTest("fake", "example.org", fake)

	// Reading: "@" comes back as "".
	records, err := p.Get(ctx, "", "")
	require.NoError(t, err)
	require.Len(t, records, 1)
	asrt.Empty(records[0].Name, "libdns's @ must become protean's empty apex name")

	// And "@" is accepted as an input spelling of the same thing.
	records, err = p.Get(ctx, "", "@")
	require.NoError(t, err)
	asrt.Len(records, 1)

	// Writing: "" goes out as "@".
	require.NoError(t, p.Upsert(ctx, "", []provider.Record{
		{Name: "", Type: provider.TypeA, Value: "203.0.113.2"},
	}))

	require.Len(t, fake.set, 1)
	asrt.Equal("@", fake.set[0].RR().Name, "protean's empty apex name must become libdns's @")
}

// A and AAAA must become libdns.Address and TXT libdns.TXT, not an opaque RR:
// libdns documents that implementations should receive the typed structs, and
// some parse them differently.
func TestLibdnsAdapterUpsertSendsTypedRecords(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := &fakeLibdns{}
	p := provider.NewLibdnsAdapterForTest("fake", "example.org", fake)

	require.NoError(t, p.Upsert(ctx, "", []provider.Record{
		{Name: "dyn", Type: provider.TypeA, Value: "203.0.113.1", TTL: 90 * time.Second},
		{Name: "dyn", Type: provider.TypeAAAA, Value: "2001:db8::1"},
		{Name: "_acme-challenge", Type: provider.TypeTXT, Value: "token"},
	}))

	require.Len(t, fake.set, 3)

	ipv4, ok := fake.set[0].(libdns.Address)
	require.True(t, ok, "an A record must be sent as libdns.Address, got %T", fake.set[0])
	asrt.Equal("203.0.113.1", ipv4.IP.String())
	asrt.Equal(90*time.Second, ipv4.TTL)

	ipv6, ok := fake.set[1].(libdns.Address)
	require.True(t, ok, "an AAAA record must be sent as libdns.Address, got %T", fake.set[1])
	asrt.Equal("2001:db8::1", ipv6.IP.String())
	asrt.Equal(provider.DefaultTTL, ipv6.TTL, "a zero TTL takes protean's default")

	txt, ok := fake.set[2].(libdns.TXT)
	require.True(t, ok, "a TXT record must be sent as libdns.TXT, got %T", fake.set[2])
	asrt.Equal("token", txt.Text)
}

// An IPv4-mapped IPv6 value must not become an AAAA record holding an IPv4
// address.
func TestLibdnsAdapterUnmapsIPv4MappedAddresses(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := &fakeLibdns{}
	p := provider.NewLibdnsAdapterForTest("fake", "example.org", fake)

	require.NoError(t, p.Upsert(ctx, "", []provider.Record{
		{Name: "dyn", Type: provider.TypeA, Value: "::ffff:203.0.113.1"},
	}))

	require.Len(t, fake.set, 1)
	addr, ok := fake.set[0].(libdns.Address)
	require.True(t, ok)
	asrt.Equal("203.0.113.1", addr.IP.String())
	asrt.True(addr.IP.Is4(), "the address must be stored as IPv4, not IPv4-mapped IPv6")
}

func TestLibdnsAdapterValidatesBeforeCalling(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := &fakeLibdns{}
	p := provider.NewLibdnsAdapterForTest("fake", "example.org", fake)

	// An AAAA record holding an IPv4 address is rejected before any provider
	// call, so a bad record costs no API quota and leaves no partial write.
	err := p.Upsert(ctx, "", []provider.Record{
		{Name: "dyn", Type: provider.TypeAAAA, Value: "203.0.113.1"},
	})
	asrt.Error(err)
	asrt.Empty(fake.set, "nothing may be sent when validation fails")

	asrt.Error(p.Upsert(ctx, "", nil), "an empty batch is an error")
	asrt.Error(p.Delete(ctx, "", nil))
}

func TestLibdnsAdapterDelete(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := &fakeLibdns{}
	p := provider.NewLibdnsAdapterForTest("fake", "example.org", fake)

	require.NoError(t, p.Delete(ctx, "", []provider.Record{
		{Name: "dyn", Type: provider.TypeA, Value: "203.0.113.1"},
	}))

	require.Len(t, fake.deleted, 1)
	asrt.Equal("dyn", fake.deleted[0].RR().Name)
	asrt.Equal(provider.TypeA, fake.deleted[0].RR().Type)
}

// The configured zone is used when the caller passes none, which is the normal
// case - a provider instance manages one zone.
func TestLibdnsAdapterFallsBackToTheConfiguredZone(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := &fakeLibdns{}
	p := provider.NewLibdnsAdapterForTest("fake", "example.org", fake)

	_, err := p.Get(ctx, "", "dyn")
	require.NoError(t, err)
	asrt.Equal("example.org.", fake.zone, "libdns takes an absolute zone name")

	_, err = p.Get(ctx, "other.example", "dyn")
	require.NoError(t, err)
	asrt.Equal("other.example.", fake.zone, "an explicit zone overrides the configured one")

	// A zone already given as an FQDN is passed through rather than acquiring
	// a second dot.
	_, err = p.Get(ctx, "third.example.", "dyn")
	require.NoError(t, err)
	asrt.Equal("third.example.", fake.zone)
}

func TestLibdnsAdapterPropagatesErrors(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	sentinel := errors.New("credentials rejected")

	fake := &fakeLibdns{getErr: sentinel, setErr: sentinel, delErr: sentinel}
	p := provider.NewLibdnsAdapterForTest("fake", "example.org", fake)

	_, err := p.Get(ctx, "", "dyn")
	asrt.ErrorIs(err, sentinel)
	asrt.Contains(err.Error(), "fake", "the error must name which provider instance failed")

	asrt.ErrorIs(p.Upsert(ctx, "", []provider.Record{
		{Name: "dyn", Type: provider.TypeA, Value: "203.0.113.1"},
	}), sentinel)

	asrt.ErrorIs(p.Delete(ctx, "", []provider.Record{
		{Name: "dyn", Type: provider.TypeA, Value: "203.0.113.1"},
	}), sentinel)

	// Verify backs `provider test`, and must fail when the credentials do.
	asrt.ErrorIs(provider.VerifyForTest(p, ctx, ""), sentinel)
}

// Verify must not write anything: `provider test` on a live zone has to be
// safe to run.
func TestLibdnsAdapterVerifyOnlyReads(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	fake := &fakeLibdns{}
	p := provider.NewLibdnsAdapterForTest("fake", "example.org", fake)

	asrt.NoError(provider.VerifyForTest(p, ctx, ""))
	asrt.Equal(1, fake.getCalls)
	asrt.Empty(fake.set, "provider test must not write")
	asrt.Empty(fake.deleted, "provider test must not delete")
}
