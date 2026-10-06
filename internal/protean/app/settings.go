package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/adnoctem/netory/pkg/kv"
)

// settingsKey holds the whole settings document under one key.
//
// One document rather than a key per setting, because `config list` and the
// server's startup both want all of them, and a single read is cheaper and
// cannot observe a half-applied change the way several reads could.
const settingsKey = "settings"

// Setting names, as `protean config set` accepts them.
const (
	SettingLogLevel             = "log.level"
	SettingAddressRetention     = "retention.address_history"
	SettingRateLimitPerHost     = "ratelimit.per_host"
	SettingRateLimitPerSource   = "ratelimit.per_source"
	SettingRateLimitWindow      = "ratelimit.window"
	SettingAuthFailureThreshold = "events.auth_failure_threshold"
	SettingNotifyDedupWindow    = "events.dedup_window"
)

// Defaults for the runtime settings.
const (
	// DefaultAddressRetention bounds how long address history is kept.
	//
	// IP addresses are personal data (section 9.3), so this is a
	// GDPR-relevant setting and not merely a housekeeping one. 90 days is the
	// value protean ships with: long enough to investigate "when did this host
	// last move", short enough to be defensible as a retention period, and the
	// same order as the conventional default for access logs. An operator who
	// needs a different number sets one; an operator who needs none sets zero,
	// which disables history entirely.
	DefaultAddressRetention = 90 * 24 * time.Hour

	// DefaultRateLimitPerHost bounds updates per host per window. A dynDNS
	// client that updates more than this is misconfigured: the address does
	// not change that often, and each update is a provider API call.
	DefaultRateLimitPerHost = 60

	// DefaultRateLimitPerSource bounds requests per source address per window,
	// which is what limits an unauthenticated attacker guessing tokens.
	DefaultRateLimitPerSource = 120

	// DefaultRateLimitWindow is the window both limits are counted over.
	DefaultRateLimitWindow = time.Hour

	// DefaultAuthFailureThreshold is how many failures for one host or source
	// trigger an auth.failed event. One typo should not page anyone.
	DefaultAuthFailureThreshold = 5
)

// Settings are the runtime-configurable values, stored in the database and
// managed over the admin socket.
//
// Anything here can be changed without a restart, which is the whole reason it
// is not in pkg/config: the bootstrap values there are needed to open the
// database, so they cannot live in it.
type Settings struct {
	// AddressRetention bounds address history. Zero disables history.
	AddressRetention time.Duration `json:"address_retention"`

	// RateLimitPerHost and RateLimitPerSource bound updates per window. Zero
	// disables the respective limit.
	RateLimitPerHost   int `json:"rate_limit_per_host"`
	RateLimitPerSource int `json:"rate_limit_per_source"`

	// RateLimitWindow is the window the limits are counted over.
	RateLimitWindow time.Duration `json:"rate_limit_window"`

	// AuthFailureThreshold is how many failures trigger an auth.failed event.
	AuthFailureThreshold int `json:"auth_failure_threshold"`

	// NotifyDedupWindow collapses identical events. Zero takes the bus default.
	NotifyDedupWindow time.Duration `json:"notify_dedup_window"`

	// LogLevel overrides the bootstrap log level at runtime.
	LogLevel string `json:"log_level,omitempty"`
}

// DefaultSettings returns the shipped defaults.
func DefaultSettings() Settings {
	return Settings{
		AddressRetention:     DefaultAddressRetention,
		RateLimitPerHost:     DefaultRateLimitPerHost,
		RateLimitPerSource:   DefaultRateLimitPerSource,
		RateLimitWindow:      DefaultRateLimitWindow,
		AuthFailureThreshold: DefaultAuthFailureThreshold,
	}
}

// settingSpec describes one setting for get, set and list.
type settingSpec struct {
	// describe renders the current value.
	describe func(Settings) string

	// apply parses a new value into the settings.
	apply func(*Settings, string) error

	// help is the one-line description `config list` shows.
	help string
}

// settingSpecs is the single source of truth for which settings exist.
//
// Declaring them in a table rather than a switch means `config list`, `config
// get` and `config set` cannot disagree about the set of valid names - adding a
// setting in one place and forgetting another is the failure this avoids.
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
	SettingAddressRetention: {
		help: "how long address history is kept; 0 disables history (GDPR-relevant)",
		describe: func(s Settings) string {
			if s.AddressRetention == 0 {
				return "0 (history disabled)"
			}

			return s.AddressRetention.String()
		},
		apply: func(s *Settings, value string) error {
			return applyDuration(value, &s.AddressRetention, true)
		},
	},
	SettingRateLimitPerHost: {
		help:     "updates allowed per host per window; 0 disables the limit",
		describe: func(s Settings) string { return strconv.Itoa(s.RateLimitPerHost) },
		apply:    func(s *Settings, value string) error { return applyCount(value, &s.RateLimitPerHost) },
	},
	SettingRateLimitPerSource: {
		help:     "requests allowed per source address per window; 0 disables the limit",
		describe: func(s Settings) string { return strconv.Itoa(s.RateLimitPerSource) },
		apply:    func(s *Settings, value string) error { return applyCount(value, &s.RateLimitPerSource) },
	},
	SettingRateLimitWindow: {
		help:     "the window both rate limits are counted over",
		describe: func(s Settings) string { return s.RateLimitWindow.String() },
		apply: func(s *Settings, value string) error {
			return applyDuration(value, &s.RateLimitWindow, false)
		},
	},
	SettingAuthFailureThreshold: {
		help:     "authentication failures for one host or source before an auth.failed event",
		describe: func(s Settings) string { return strconv.Itoa(s.AuthFailureThreshold) },
		apply:    func(s *Settings, value string) error { return applyCount(value, &s.AuthFailureThreshold) },
	},
	SettingNotifyDedupWindow: {
		help: "window within which identical events are collapsed; 0 uses the default",
		describe: func(s Settings) string {
			if s.NotifyDedupWindow == 0 {
				return "0 (the default window)"
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
		return fmt.Errorf("must be a duration such as 24h or 90m, got %q", value)
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

// applyCount parses a non-negative integer setting.
func applyCount(value string, target *int) error {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("must be a whole number, got %q", value)
	}

	if parsed < 0 {
		return fmt.Errorf("must not be negative, got %d", parsed)
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

// Set applies a new value to one setting, returning the updated Settings. It
// does not mutate the receiver, so a rejected value leaves nothing half-applied.
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

// All renders every setting for `config list`.
func (s Settings) All() map[string]string {
	out := make(map[string]string, len(settingSpecs))
	for name, spec := range settingSpecs {
		out[name] = spec.describe(s)
	}

	return out
}

// unknownSetting builds an error naming the valid settings, since the list is
// fixed and short enough to print.
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
//
// A missing document is not an error: a fresh database has no settings, and the
// server must start anyway.
func (s *SettingsStore) Load(ctx context.Context) (Settings, error) {
	raw, err := s.store.Get(ctx, settingsKey)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return DefaultSettings(), nil
		}

		return Settings{}, fmt.Errorf("read settings: %w", err)
	}

	// Decoded over the defaults, so a document written by an older version
	// that lacks a field gets that field's default rather than its zero value.
	// Without this, adding a setting would silently disable it for every
	// existing installation.
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
