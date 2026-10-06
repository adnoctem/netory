package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/adnoctem/netory/internal/signpost/bundle"
	"github.com/adnoctem/netory/pkg/kv"
)

// settingsKey holds the whole settings document under one key, for the same
// reason protean's does: `config list` and startup both want all of them, and
// one read cannot observe a half-applied change.
const settingsKey = "settings"

// Setting names, as `signpost config set` accepts them.
const (
	SettingLogLevel            = "log.level"
	SettingServeAlias          = "serve.alias"
	SettingServeVersioned      = "serve.versioned"
	SettingCacheAliasMaxAge    = "cache.alias_max_age"
	SettingCacheVersionMaxAge  = "cache.versioned_max_age"
	SettingAccessLogAddress    = "accesslog.client_address"
	SettingRequireSignature    = "publish.require_signature"
	SettingSigningKey          = "publish.signing_key"
	SettingAllowTruncationSkip = "publish.allow_truncation_opt_out"
	SettingNotifyDedupWindow   = "events.dedup_window"
)

// AccessLogAddress selects how much of a client address is recorded.
type AccessLogAddress string

// The access-log address modes (§9.7).
const (
	// AccessLogFull records the client address verbatim.
	AccessLogFull AccessLogAddress = "full"

	// AccessLogAnonymised truncates the address before it is recorded.
	AccessLogAnonymised AccessLogAddress = "anonymised"

	// AccessLogOff records no client address at all.
	AccessLogOff AccessLogAddress = "off"
)

// Masks applied by AccessLogAnonymised.
//
// A /24 for IPv4 and a /48 for IPv6: enough to keep an access log useful for
// seeing where traffic comes from, not enough to identify a subscriber. These
// are the masks data-protection authorities have accepted for analytics
// anonymisation, which is the closest thing to settled practice here.
const (
	anonymiseIPv4Bits = 24
	anonymiseIPv6Bits = 48
)

// Defaults for the runtime settings.
const (
	// DefaultCacheAliasMaxAge is how long an alias route may be cached.
	//
	// Short by necessity. An alias route changes meaning at the next publish,
	// and a client that caches it for an hour would install the previous
	// release for an hour after a rollback that existed to stop exactly that.
	DefaultCacheAliasMaxAge = 60 * time.Second

	// DefaultCacheVersionMaxAge is how long a versioned route may be cached.
	//
	// A versioned route is immutable by construction - its release can never
	// be rewritten - so it is cacheable for as long as HTTP allows. A year is
	// the conventional maximum for immutable content.
	DefaultCacheVersionMaxAge = 365 * 24 * time.Hour

	// DefaultAccessLogAddress is the shipped access-log mode.
	//
	// Anonymised rather than full: a client address is personal data and
	// signpost's access log exists to show traffic shape, not to identify
	// downloaders. An operator investigating abuse can set "full" knowingly,
	// which is the right way round - the privacy-preserving choice is the one
	// that needs no decision.
	DefaultAccessLogAddress = AccessLogAnonymised
)

// Settings are signpost's runtime-configurable values, stored in the database
// and managed over the admin socket.
type Settings struct {
	// ServeAlias is the alias the unversioned public routes are served from.
	ServeAlias string `json:"serve_alias"`

	// ServeVersioned enables the /v<release>/<path> routes of §5.
	ServeVersioned bool `json:"serve_versioned"`

	// CacheAliasMaxAge and CacheVersionMaxAge are the two halves of the §5.2
	// cache split.
	CacheAliasMaxAge   time.Duration `json:"cache_alias_max_age"`
	CacheVersionMaxAge time.Duration `json:"cache_version_max_age"`

	// AccessLogAddress is how much of a client address the access log records.
	AccessLogAddress AccessLogAddress `json:"access_log_address"`

	// RequireSignature refuses a publish without a verified signature.
	RequireSignature bool `json:"require_signature"`

	// SigningKey is the trusted minisign public key, in the CLI's one-line
	// format. Empty means no key is configured, and signature verification is
	// then possible only by supplying a key at publish time.
	SigningKey string `json:"signing_key,omitempty"`

	// AllowTruncationSkip permits a manifest to opt a route out of the §6.3
	// check. Set false to reject any bundle that tries.
	AllowTruncationSkip bool `json:"allow_truncation_skip"`

	// NotifyDedupWindow collapses identical events.
	//
	// Zero disables collapsing, which is signpost's default and the opposite
	// of protean's. Every event here is a human administrative act, and the
	// sequence deduplication would collapse - publish, notice, roll back - is
	// the one an operator most needs to hear in full. See State.startBus.
	NotifyDedupWindow time.Duration `json:"notify_dedup_window"`

	// LogLevel overrides the bootstrap log level at runtime.
	LogLevel string `json:"log_level,omitempty"`
}

// DefaultSettings returns the shipped defaults.
func DefaultSettings() Settings {
	return Settings{
		ServeAlias:          DefaultAlias,
		ServeVersioned:      true,
		CacheAliasMaxAge:    DefaultCacheAliasMaxAge,
		CacheVersionMaxAge:  DefaultCacheVersionMaxAge,
		AccessLogAddress:    DefaultAccessLogAddress,
		AllowTruncationSkip: true,
	}
}

// RecordAddress renders a client address for the access log, applying the
// configured mode.
//
// The anonymisation happens here, before the address reaches a log handler,
// rather than in the handler: a record that leaves this process carrying a full
// address cannot be un-sent, so the only place the choice can be enforced is
// the one place that builds the record.
func (s Settings) RecordAddress(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}

	addr = addr.Unmap()

	switch s.AccessLogAddress {
	case AccessLogOff:
		return ""
	case AccessLogAnonymised:
		bits := anonymiseIPv6Bits
		if addr.Is4() {
			bits = anonymiseIPv4Bits
		}

		prefix, err := addr.Prefix(bits)
		if err != nil {
			// Unreachable for a valid address and a fixed bit count, but
			// falling back to the empty string rather than the full address
			// keeps a bug here from becoming a privacy incident.
			return ""
		}

		return prefix.String()
	case AccessLogFull:
		return addr.String()
	default:
		// An unrecognised stored value is treated as the safe mode, not as
		// "full". A settings document from a future version must not silently
		// start recording more than this build knows it agreed to.
		return ""
	}
}

// settingSpec describes one setting for get, set and list.
type settingSpec struct {
	describe func(Settings) string
	apply    func(*Settings, string) error
	help     string
}

// settingSpecs is the single source of truth for which settings exist, for the
// same reason protean's is: `config get`, `set` and `list` cannot disagree
// about the set of valid names.
var settingSpecs = map[string]settingSpec{
	SettingLogLevel: {
		help: "log level: debug, info, warn or error",
		describe: func(s Settings) string {
			if s.LogLevel == "" {
				return "(from the bootstrap configuration)"
			}

			return s.LogLevel
		},
		apply: func(s *Settings, value string) error {
			switch value {
			case "debug", "info", "warn", "error":
				s.LogLevel = value

				return nil
			case "":
				s.LogLevel = ""

				return nil
			default:
				return fmt.Errorf("must be one of debug, info, warn, error, got %q", value)
			}
		},
	},
	SettingServeAlias: {
		help:     "the alias the unversioned public routes are served from",
		describe: func(s Settings) string { return s.ServeAlias },
		apply: func(s *Settings, value string) error {
			if err := ValidateAlias(value); err != nil {
				return err
			}

			s.ServeAlias = value

			return nil
		},
	},
	SettingServeVersioned: {
		help:     "serve /v<release>/<path> routes for pinned installs",
		describe: func(s Settings) string { return strconv.FormatBool(s.ServeVersioned) },
		apply:    func(s *Settings, value string) error { return applyBool(value, &s.ServeVersioned) },
	},
	SettingCacheAliasMaxAge: {
		help:     "how long an alias route may be cached; keep it short, it changes on publish",
		describe: func(s Settings) string { return s.CacheAliasMaxAge.String() },
		apply: func(s *Settings, value string) error {
			return applyDuration(value, &s.CacheAliasMaxAge, true)
		},
	},
	SettingCacheVersionMaxAge: {
		help:     "how long a versioned route may be cached; it is immutable, so this can be long",
		describe: func(s Settings) string { return s.CacheVersionMaxAge.String() },
		apply: func(s *Settings, value string) error {
			return applyDuration(value, &s.CacheVersionMaxAge, true)
		},
	},
	SettingAccessLogAddress: {
		help:     "client address in the access log: full, anonymised or off (GDPR-relevant)",
		describe: func(s Settings) string { return string(s.AccessLogAddress) },
		apply: func(s *Settings, value string) error {
			switch AccessLogAddress(value) {
			case AccessLogFull, AccessLogAnonymised, AccessLogOff:
				s.AccessLogAddress = AccessLogAddress(value)

				return nil
			default:
				return fmt.Errorf("must be one of full, anonymised, off, got %q", value)
			}
		},
	},
	SettingRequireSignature: {
		help:     "refuse to publish a bundle without a verified signature",
		describe: func(s Settings) string { return strconv.FormatBool(s.RequireSignature) },
		apply:    func(s *Settings, value string) error { return applyBool(value, &s.RequireSignature) },
	},
	SettingSigningKey: {
		help: "the trusted minisign public key, as `minisign -G` prints it",
		describe: func(s Settings) string {
			if s.SigningKey == "" {
				return "(none)"
			}

			// Shown in full, unlike a credential: a public key is public, and
			// an operator checking that the right key is trusted needs to see
			// which one it is.
			return s.SigningKey
		},
		apply: func(s *Settings, value string) error {
			if value == "" {
				s.SigningKey = ""

				return nil
			}

			// Parsed before being stored, so a mistyped key is rejected now
			// rather than at the next publish - which, with
			// publish.require_signature set, is when publishing stops working
			// for reasons that look nothing like a typo.
			if _, err := bundle.ParsePublicKey(value); err != nil {
				return err
			}

			s.SigningKey = value

			return nil
		},
	},
	SettingAllowTruncationSkip: {
		help:     "allow a manifest to opt a route out of the truncation check",
		describe: func(s Settings) string { return strconv.FormatBool(s.AllowTruncationSkip) },
		apply:    func(s *Settings, value string) error { return applyBool(value, &s.AllowTruncationSkip) },
	},
	SettingNotifyDedupWindow: {
		help: "window within which identical events are collapsed; 0 disables collapsing",
		describe: func(s Settings) string {
			if s.NotifyDedupWindow == 0 {
				return "0 (every event is delivered)"
			}

			return s.NotifyDedupWindow.String()
		},
		apply: func(s *Settings, value string) error {
			return applyDuration(value, &s.NotifyDedupWindow, true)
		},
	},
}

// applyDuration parses a duration setting.
func applyDuration(value string, target *time.Duration, allowZero bool) error {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("must be a duration such as 60s or 24h, got %q", value)
	}

	if parsed < 0 {
		return fmt.Errorf("must not be negative, got %s", parsed)
	}

	if parsed == 0 && !allowZero {
		return errors.New("must be greater than zero")
	}

	*target = parsed

	return nil
}

// applyBool parses a boolean setting.
func applyBool(value string, target *bool) error {
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("must be true or false, got %q", value)
	}

	*target = parsed

	return nil
}

// SettingNames returns the valid setting names, sorted.
func SettingNames() []string {
	names := slices.Collect(maps.Keys(settingSpecs))
	sort.Strings(names)

	return names
}

// SettingHelp returns the one-line description of a setting.
func SettingHelp(name string) (string, bool) {
	spec, ok := settingSpecs[name]
	if !ok {
		return "", false
	}

	return spec.help, true
}

// Get returns the current value of one setting, rendered for display.
func (s Settings) Get(name string) (string, error) {
	spec, ok := settingSpecs[name]
	if !ok {
		return "", unknownSetting(name)
	}

	return spec.describe(s), nil
}

// Set applies a new value to one setting, returning the updated Settings. The
// receiver is not mutated, so a rejected value leaves nothing half-applied.
func (s Settings) Set(name, value string) (Settings, error) {
	spec, ok := settingSpecs[name]
	if !ok {
		return s, unknownSetting(name)
	}

	updated := s
	if err := spec.apply(&updated, value); err != nil {
		return s, fmt.Errorf("setting %s: %w", name, err)
	}

	return updated, nil
}

// All renders every setting for `config list` and `config view`.
func (s Settings) All() map[string]string {
	out := make(map[string]string, len(settingSpecs))
	for name, spec := range settingSpecs {
		out[name] = spec.describe(s)
	}

	return out
}

// unknownSetting builds an error naming the valid settings.
func unknownSetting(name string) error {
	return fmt.Errorf("unknown setting %q, valid settings are: %v", name, SettingNames())
}

// SettingsStore persists Settings.
type SettingsStore struct {
	store kv.Handle
}

// NewSettingsStore returns the settings repository over a namespace handle.
func NewSettingsStore(store kv.Handle) *SettingsStore { return &SettingsStore{store: store} }

// Load returns the stored settings, or the defaults when none have been saved.
func (s *SettingsStore) Load(ctx context.Context) (Settings, error) {
	raw, err := s.store.Get(ctx, settingsKey)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return DefaultSettings(), nil
		}

		return Settings{}, fmt.Errorf("read settings: %w", err)
	}

	// Decoded over the defaults, so a document written by an older version
	// that lacks a field gets that field's default rather than its zero value
	// - which for serve_versioned would silently turn versioned routes off.
	settings := DefaultSettings()
	if err := json.Unmarshal(raw, &settings); err != nil {
		return Settings{}, fmt.Errorf("decode settings: %w", err)
	}

	return settings, nil
}

// Save stores the settings.
func (s *SettingsStore) Save(ctx context.Context, settings Settings) error {
	encoded, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("encode settings: %w", err)
	}

	if err := s.store.Set(ctx, settingsKey, encoded); err != nil {
		return fmt.Errorf("store settings: %w", err)
	}

	return nil
}
