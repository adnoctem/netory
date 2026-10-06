package provider

import "context"

// Compiled only into the test binary, so the adapter can be exercised against
// a fake libdns client without widening the package's shipped API.

// FakeLibdnsClient is the minimal shape the adapter needs, re-exported so a
// test can supply one.
type FakeLibdnsClient = libdnsClient

// NewLibdnsAdapterForTest builds the adapter directly over a fake client.
func NewLibdnsAdapterForTest(name, zone string, client FakeLibdnsClient) Provider {
	return &libdnsAdapter{
		name:     name,
		kind:     "fake",
		zone:     zone,
		client:   client,
		redacted: map[string]string{"credential": "(set)"},
	}
}

// VerifyForTest calls Verify on an adapter built by NewLibdnsAdapterForTest.
func VerifyForTest(p Provider, ctx context.Context, zone string) error {
	return p.(Verifier).Verify(ctx, zone)
}
