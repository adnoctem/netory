package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
)

func newSettingsStore(t *testing.T) *app.SettingsStore {
	t.Helper()

	store, err := badgerkv.New(badgerkv.Options{InMemory: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	handle, err := kv.In(store, "settings")
	require.NoError(t, err)

	return app.NewSettingsStore(handle)
}

// A fresh database has no settings document, and the server must start anyway.
func TestSettingsLoadDefaultsOnAFreshDatabase(t *testing.T) {
	asrt := assert.New(t)

	settings, err := newSettingsStore(t).Load(context.Background())
	asrt.NoError(err)
	asrt.Equal(app.DefaultSettings(), settings)
}

func TestSettingsRoundTrip(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	store := newSettingsStore(t)

	settings := app.DefaultSettings()
	settings.RateLimitPerHost = 7
	require.NoError(t, store.Save(ctx, settings))

	loaded, err := store.Load(ctx)
	asrt.NoError(err)
	asrt.Equal(7, loaded.RateLimitPerHost)
}

// A document written by an older version that lacks a field must get that
// field's default, not its zero value. Without this, adding a setting would
// silently disable it for every existing installation.
func TestSettingsLoadFillsMissingFieldsWithDefaults(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	store, err := badgerkv.New(badgerkv.Options{InMemory: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	handle, err := kv.In(store, "settings")
	require.NoError(t, err)

	// A document carrying only one field, as an older version would have
	// written it.
	require.NoError(t, handle.Set(ctx, "settings", []byte(`{"rate_limit_per_host":9}`)))

	loaded, err := app.NewSettingsStore(handle).Load(ctx)
	asrt.NoError(err)
	asrt.Equal(9, loaded.RateLimitPerHost, "the stored field is honoured")
	asrt.Equal(app.DefaultRateLimitPerSource, loaded.RateLimitPerSource,
		"a field absent from the document must take its default, not zero")
	asrt.Equal(app.DefaultAddressRetention, loaded.AddressRetention)
	asrt.Equal(app.DefaultRateLimitWindow, loaded.RateLimitWindow)
}

// The setting table is the single source of truth, so get, set and list cannot
// disagree about which settings exist.
func TestSettingNamesAreConsistent(t *testing.T) {
	asrt := assert.New(t)

	names := app.SettingNames()
	asrt.NotEmpty(names)

	settings := app.DefaultSettings()
	all := settings.All()

	asrt.Len(all, len(names), "All must cover exactly the declared settings")

	for _, name := range names {
		value, err := settings.Get(name)
		asrt.NoError(err, name)
		asrt.NotEmpty(value, "%s rendered as empty, which reads as a missing value", name)

		help, ok := app.SettingHelp(name)
		asrt.True(ok, name)
		asrt.NotEmpty(help, "%s has no description for `config list`", name)

		asrt.Contains(all, name)
	}
}

func TestSettingsSetValidates(t *testing.T) {
	asrt := assert.New(t)

	settings := app.DefaultSettings()

	updated, err := settings.Set(app.SettingRateLimitPerHost, "120")
	asrt.NoError(err)
	asrt.Equal(120, updated.RateLimitPerHost)

	// Set does not mutate the receiver, so a rejected value leaves nothing
	// half-applied.
	asrt.Equal(app.DefaultRateLimitPerHost, settings.RateLimitPerHost)

	updated, err = settings.Set(app.SettingAddressRetention, "720h")
	asrt.NoError(err)
	asrt.Equal(720*time.Hour, updated.AddressRetention)

	// Zero disables address history, which is a legitimate GDPR choice.
	updated, err = settings.Set(app.SettingAddressRetention, "0s")
	asrt.NoError(err)
	asrt.Zero(updated.AddressRetention)

	// But the rate-limit window cannot be zero: a zero window is not a
	// disabled limit, it is a nonsensical one.
	_, err = settings.Set(app.SettingRateLimitWindow, "0s")
	asrt.Error(err)

	for _, bad := range []struct{ name, value string }{
		{app.SettingRateLimitPerHost, "lots"},
		{app.SettingRateLimitPerHost, "-1"},
		{app.SettingRateLimitPerSource, "-5"},
		{app.SettingAddressRetention, "forever"},
		{app.SettingAddressRetention, "-1h"},
		{app.SettingRateLimitWindow, "never"},
		{app.SettingAuthFailureThreshold, "-1"},
		{app.SettingLogLevel, "chatty"},
	} {
		_, err := settings.Set(bad.name, bad.value)
		asrt.Error(err, "%s=%s", bad.name, bad.value)
	}

	// An unknown setting names the valid ones, since the list is fixed and
	// short enough to print.
	_, err = settings.Set("nonsense", "1")
	asrt.Error(err)
	asrt.Contains(err.Error(), app.SettingRateLimitPerHost)

	_, err = settings.Get("nonsense")
	asrt.Error(err)
}

// The retention default is a GDPR-relevant value, so it is asserted rather
// than left to drift.
func TestAddressRetentionDefaultIsNinetyDays(t *testing.T) {
	assert.Equal(t, 90*24*time.Hour, app.DefaultAddressRetention,
		"the shipped retention default is the documented 90 days")
}

// The event taxonomy must match the one docs/ARCHITECTURE.md documents.
func TestEventTaxonomy(t *testing.T) {
	asrt := assert.New(t)

	types := app.EventTypes()

	names := make([]string, 0, len(types))
	for _, typ := range types {
		names = append(names, string(typ))
	}

	asrt.ElementsMatch([]string{
		"host.updated",
		"host.update_failed",
		"auth.failed",
		"token.created",
		"token.revoked",
		"provider.failed",
	}, names, "the taxonomy must match the documented one")
}

func TestEventBuilders(t *testing.T) {
	asrt := assert.New(t)

	updated := app.HostUpdated("dyn.example.org", "203.0.113.1", "2001:db8::1")
	asrt.Equal(app.EventHostUpdated, updated.Type)
	asrt.Equal("dyn.example.org", updated.Subject)
	asrt.Equal("203.0.113.1", updated.Field("ipv4"))
	asrt.Equal("2001:db8::1", updated.Field("ipv6"))

	// An absent family is omitted rather than recorded as empty.
	updated = app.HostUpdated("dyn.example.org", "203.0.113.1", "")
	asrt.Empty(updated.Field("ipv6"))

	failed := app.HostUpdateFailed("dyn.example.org", "cf-main", assert.AnError)
	asrt.Equal(app.EventHostUpdateFailed, failed.Type)
	asrt.Equal("cf-main", failed.Field("provider"))
	asrt.NotEmpty(failed.Field("error"))

	authFailed := app.AuthFailed("dyn.example.org", "203.0.113.9", 5)
	asrt.Equal(app.EventAuthFailed, authFailed.Type)
	asrt.Equal("5", authFailed.Field("failures"))
	asrt.Equal("203.0.113.9", authFailed.Field("source"))

	created := app.TokenCreated("dyn.example.org", "abc123", "fmj(uid=1000)")
	asrt.Equal(app.EventTokenCreated, created.Type)
	asrt.Equal("abc123", created.Field("token_id"))
	asrt.Contains(created.Field("by"), "uid=1000", "an audit event must name who did it")
}
