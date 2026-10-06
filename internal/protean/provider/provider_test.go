package provider_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/adnoctem/netory/internal/protean/provider"
)

func TestKindsAreRegistered(t *testing.T) {
	asrt := assert.New(t)

	// Compiled in and registered at init, so `provider list` can state exactly
	// what this binary supports.
	asrt.Equal(
		[]string{provider.KindCloudflare, provider.KindRoute53, provider.KindSpaceship},
		provider.Kinds(),
	)
}

func TestNewRejectsUnknownKind(t *testing.T) {
	asrt := assert.New(t)

	_, err := provider.New(provider.Config{Name: "p", Kind: "gandi", Zone: "example.org"})
	asrt.ErrorIs(err, provider.ErrUnknownKind)
	asrt.Contains(err.Error(), provider.KindCloudflare, "the error must list what is available")
}

func TestNewRequiresNameAndZone(t *testing.T) {
	asrt := assert.New(t)

	_, err := provider.New(provider.Config{Kind: provider.KindCloudflare, Zone: "example.org"})
	asrt.Error(err, "a name is required")

	_, err = provider.New(provider.Config{Name: "p", Kind: provider.KindCloudflare})
	asrt.Error(err, "a zone is required")
}

// An IPv4 address in an AAAA record is accepted by some provider APIs and then
// serves a broken zone, so the mismatch is caught here where the error can
// name the problem.
func TestRecordValidate(t *testing.T) {
	asrt := assert.New(t)

	for name, record := range map[string]provider.Record{
		"A with IPv4":    {Name: "dyn", Type: provider.TypeA, Value: "203.0.113.1"},
		"AAAA with IPv6": {Name: "dyn", Type: provider.TypeAAAA, Value: "2001:db8::1"},
		"TXT":            {Name: "_acme-challenge", Type: provider.TypeTXT, Value: "token"},
		"apex A":         {Name: "", Type: provider.TypeA, Value: "203.0.113.1"},
	} {
		asrt.NoError(record.Validate(), name)
	}

	for name, record := range map[string]provider.Record{
		"no type":           {Name: "dyn", Value: "203.0.113.1"},
		"unsupported type":  {Name: "dyn", Type: "MX", Value: "mail.example.org"},
		"no value":          {Name: "dyn", Type: provider.TypeA},
		"A with IPv6":       {Name: "dyn", Type: provider.TypeA, Value: "2001:db8::1"},
		"A with garbage":    {Name: "dyn", Type: provider.TypeA, Value: "not-an-ip"},
		"AAAA with IPv4":    {Name: "dyn", Type: provider.TypeAAAA, Value: "203.0.113.1"},
		"AAAA with garbage": {Name: "dyn", Type: provider.TypeAAAA, Value: "not-an-ip"},
	} {
		asrt.Error(record.Validate(), name)
	}

	// The AAAA-with-IPv4 message has to point at the fix, because this is the
	// mistake an operator will actually make.
	err := provider.Record{Name: "dyn", Type: provider.TypeAAAA, Value: "203.0.113.1"}.Validate()
	asrt.Contains(err.Error(), "use an A record")
}

func TestValidateAll(t *testing.T) {
	asrt := assert.New(t)

	asrt.Error(provider.ValidateAll(nil), "an empty batch is an error, not a no-op")

	err := provider.ValidateAll([]provider.Record{
		{Name: "a", Type: provider.TypeA, Value: "203.0.113.1"},
		{Name: "b", Type: provider.TypeA, Value: "nonsense"},
	})
	asrt.Error(err)
	asrt.Contains(err.Error(), "record 1", "the error must name which record failed")
}

func TestRecordTTLAndFQDN(t *testing.T) {
	asrt := assert.New(t)

	asrt.Equal(provider.DefaultTTL, provider.Record{}.ValidTTL(), "a zero TTL takes the default")
	asrt.Equal(provider.DefaultTTL, provider.Record{TTL: -time.Hour}.ValidTTL())
	asrt.Equal(5*time.Minute, provider.Record{TTL: 5 * time.Minute}.ValidTTL())

	asrt.Equal("dyn.example.org", provider.Record{Name: "dyn"}.FQDN("example.org"))
	asrt.Equal("dyn.example.org", provider.Record{Name: "dyn"}.FQDN("example.org."))
	asrt.Equal("example.org", provider.Record{Name: ""}.FQDN("example.org"), "an empty name is the apex")
	asrt.Equal("example.org", provider.Record{Name: "@"}.FQDN("example.org"))
}

// Credentials must not reach `provider list`.
func TestRedactedHidesCredentials(t *testing.T) {
	asrt := assert.New(t)

	cfg := provider.Config{
		Name: "cf-main",
		Kind: provider.KindCloudflare,
		Zone: "example.org",
		Settings: map[string]string{
			provider.SettingAPIToken: "cf-token-SECRET-VALUE",
		},
	}

	redacted := cfg.Redacted()
	asrt.Equal("(set)", redacted[provider.SettingAPIToken])

	for key, value := range redacted {
		asrt.NotContains(value, "SECRET-VALUE", "the token leaked through %q", key)
	}

	instance, err := provider.New(cfg)
	asrt.NoError(err)

	for key, value := range instance.Redacted() {
		asrt.NotContains(value, "SECRET-VALUE", "the token leaked through %q", key)
	}
	asrt.Equal("example.org", instance.Redacted()["zone"])
	asrt.Equal("cf-main", instance.Name())
	asrt.Equal(provider.KindCloudflare, instance.Kind())
}

func TestCloudflareRequiresAToken(t *testing.T) {
	_, err := provider.New(provider.Config{
		Name: "cf", Kind: provider.KindCloudflare, Zone: "example.org",
	})
	assert.Error(t, err)
}

// An access key without its secret silently falls back to the AWS credential
// chain and then fails somewhere far from the mistake.
func TestRoute53RejectsHalfSuppliedCredentials(t *testing.T) {
	asrt := assert.New(t)

	for name, settings := range map[string]map[string]string{
		"id without secret": {provider.SettingAccessKeyID: "AKIAEXAMPLE"},
		"secret without id": {provider.SettingSecretAccessKey: "s3cr3t"},
	} {
		_, err := provider.New(provider.Config{
			Name: "r53", Kind: provider.KindRoute53, Zone: "example.org", Settings: settings,
		})
		asrt.Error(err, name)
		asrt.Contains(err.Error(), "together", name)
	}

	// Both unset is legal: the SDK's own chain is usually what an operator on
	// EC2 or EKS wants, and it beats copying a long-lived key into the store.
	instance, err := provider.New(provider.Config{
		Name: "r53", Kind: provider.KindRoute53, Zone: "example.org",
	})
	asrt.NoError(err)
	asrt.Contains(instance.Redacted()["credentials"], "credential chain")

	// And both set is legal.
	_, err = provider.New(provider.Config{
		Name: "r53", Kind: provider.KindRoute53, Zone: "example.org",
		Settings: map[string]string{
			provider.SettingAccessKeyID:     "AKIAEXAMPLE",
			provider.SettingSecretAccessKey: "s3cr3t",
		},
	})
	asrt.NoError(err)
}

func TestSpaceshipConfigValidation(t *testing.T) {
	asrt := assert.New(t)

	base := map[string]string{
		provider.SettingAPIKey:    "key",
		provider.SettingAPISecret: "secret",
	}

	_, err := provider.New(provider.Config{
		Name: "ss", Kind: provider.KindSpaceship, Zone: "example.org", Settings: base,
	})
	asrt.NoError(err)

	for name, settings := range map[string]map[string]string{
		"no key":    {provider.SettingAPISecret: "secret"},
		"no secret": {provider.SettingAPIKey: "key"},
		"http endpoint": {
			provider.SettingAPIKey:    "key",
			provider.SettingAPISecret: "secret",
			provider.SettingEndpoint:  "http://spaceship.example",
		},
	} {
		_, err := provider.New(provider.Config{
			Name: "ss", Kind: provider.KindSpaceship, Zone: "example.org", Settings: settings,
		})
		asrt.Error(err, name)
	}
}
