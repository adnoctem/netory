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

	"github.com/adnoctem/netory/internal/pivot/auth"
	"github.com/adnoctem/netory/internal/pivot/config"
	"github.com/adnoctem/netory/pkg/kv"
)

// settingsKey holds the whole settings document under one key, so `config
// list` is one read and cannot observe a half-applied change.
const settingsKey = "settings"

// Setting names, as `pivot config set` accepts them.
const (
	SettingLogLevel             = "log.level"
	SettingFrontendMode         = "frontend.auth_mode"
	SettingFrontendPath         = "frontend.auth_path"
	SettingBackendURL           = "backend.url"
	SettingTokenLifetime        = "token.lifetime"
	SettingDefaultRateCapacity  = "ratelimit.default_burst"
	SettingDefaultRatePerSecond = "ratelimit.default_per_second"
	SettingBackendConcurrency   = "backend.concurrency"
	SettingCoalesce             = "cache.coalesce"
	SettingAuditRetention       = "audit.retention"
	SettingAccessLogAddress     = "accesslog.client_address"
	SettingNotifyDedupWindow    = "events.dedup_window"
)

// Defaults for the runtime settings.
const (
	// DefaultAuditRetention is how long pivot keeps the audit records it
	// stores itself.
	//
	// Ninety days. Worth being precise about the reasoning, since the audit
	// trail is a compliance artefact: there is no statutory
	// maximum of ninety days under GDPR - Art. 5(1)(e) is a necessity test,
	// not a number - so this is a defensible proportionate period rather than
	// "the legal limit". It matches protean's address-history default, which
	// keeps one answer to "how long does netory keep things" across the three
	// services, and an operator with a different obligation sets a different
	// value.
	DefaultAuditRetention = 90 * 24 * time.Hour

	// DefaultTokenLifetimeSetting is the shipped access-token lifetime.
	DefaultTokenLifetimeSetting = DefaultTokenLifetime
)

// AccessLogAddress selects how much of a client address is recorded.
type AccessLogAddress string

// The access-log address modes, matching signpost's so one answer covers both
// services.
const (
	AccessLogFull       AccessLogAddress = "full"
	AccessLogAnonymised AccessLogAddress = "anonymised"
	AccessLogOff        AccessLogAddress = "off"
)

// Settings are pivot's runtime-configurable values, stored in Valkey.
//
// Stored centrally rather than per replica, which is what makes `pivot config
// set` on one replica apply to all of them, and the reason these are not
// flags.
type Settings struct {
	// Frontend is how customers authenticate, and where pivot answers its own
	// token endpoint.
	FrontendMode auth.FrontendMode `json:"frontend_mode"`
	FrontendPath string            `json:"frontend_path"`

	// BackendURL is the origin requests are forwarded to.
	BackendURL string `json:"backend_url"`

	// TokenLifetime is how long an issued access token lives.
	TokenLifetime time.Duration `json:"token_lifetime"`

	// DefaultRateLimit applies to a client with no limit of its own.
	DefaultRateLimit RateLimit `json:"default_rate_limit"`

	// BackendConcurrency caps simultaneous backend calls per replica. Zero is
	// unlimited.
	BackendConcurrency int `json:"backend_concurrency"`

	// Coalesce makes identical concurrent requests share one backend call.
	Coalesce bool `json:"coalesce"`

	// AuditRetention bounds the audit records pivot stores itself.
	AuditRetention time.Duration `json:"audit_retention"`

	// AccessLogAddress is how much of a client address the access log
	// records.
	AccessLogAddress AccessLogAddress `json:"access_log_address"`

	// NotifyDedupWindow collapses identical events. Zero disables collapsing.
	NotifyDedupWindow time.Duration `json:"notify_dedup_window"`

	// LogLevel overrides the bootstrap log level at runtime.
	LogLevel string `json:"log_level,omitempty"`
}

// DefaultSettings returns the shipped defaults.
func DefaultSettings() Settings {
	return Settings{
		FrontendMode:       auth.FrontendOAuth2,
		FrontendPath:       "/api/oauth/token",
		TokenLifetime:      DefaultTokenLifetimeSetting,
		BackendConcurrency: 16,
		Coalesce:           true,
		AuditRetention:     DefaultAuditRetention,
		AccessLogAddress:   AccessLogAnonymised,

		// Deduplication off, for the same reason signpost's is: every pivot
		// event is either an administrative act or an aggregated incident
		// report, and rule.denied and client.rate_limited are already
		// aggregated at the source. Collapsing on top of that would hide the
		// second distinct incident of a minute.
		NotifyDedupWindow: 0,
	}
}

// Validate reports whether the settings are usable.
func (s Settings) Validate() error {
	if !s.FrontendMode.Valid() {
		return fmt.Errorf("app: frontend mode %q is not one of %v",
			s.FrontendMode, auth.FrontendModes())
	}

	if s.FrontendMode == auth.FrontendOAuth2 && s.FrontendPath == "" {
		return errors.New("app: oauth2 mode needs a token endpoint path")
	}

	if s.TokenLifetime <= 0 || s.TokenLifetime > MaxTokenLifetime {
		return fmt.Errorf("app: token lifetime must be between 1s and %s, got %s",
			MaxTokenLifetime, s.TokenLifetime)
	}

	if err := s.DefaultRateLimit.Validate(); err != nil {
		return err
	}

	if s.BackendConcurrency < 0 {
		return fmt.Errorf("app: backend concurrency must not be negative, got %d",
			s.BackendConcurrency)
	}

	if s.AuditRetention < 0 {
		return fmt.Errorf("app: audit retention must not be negative, got %s", s.AuditRetention)
	}

	return nil
}

// settingSpec describes one setting for get, set and list.
type settingSpec struct {
	describe func(Settings) string
	apply    func(*Settings, string) error
	help     string
}

// settingSpecs is the single source of truth for which settings exist, so
// `config get`, `set` and `list` cannot disagree about the valid names.
var settingSpecs = map[string]settingSpec{
	SettingLogLevel: {
		help:     "log level: debug, info, warn or error",
		describe: func(s Settings) string { return orDefault(s.LogLevel, "(from the bootstrap configuration)") },
		apply: func(s *Settings, value string) error {
			switch value {
			case "debug", "info", "warn", "error", "":
				s.LogLevel = value

				return nil
			default:
				return fmt.Errorf("must be one of debug, info, warn, error, got %q", value)
			}
		},
	},
	SettingFrontendMode: {
		help:     "how customers authenticate: oauth2, http-basic or bearer",
		describe: func(s Settings) string { return string(s.FrontendMode) },
		apply: func(s *Settings, value string) error {
			mode := auth.FrontendMode(value)
			if !mode.Valid() {
				return fmt.Errorf("must be one of %v, got %q", auth.FrontendModes(), value)
			}

			s.FrontendMode = mode

			return nil
		},
	},
	SettingFrontendPath: {
		help:     "path pivot answers its own token endpoint on, in oauth2 mode",
		describe: func(s Settings) string { return orDefault(s.FrontendPath, "(none)") },
		apply: func(s *Settings, value string) error {
			if value != "" && value[0] != '/' {
				return fmt.Errorf("must begin with /, got %q", value)
			}

			s.FrontendPath = value

			return nil
		},
	},
	SettingBackendURL: {
		help:     "the origin requests are forwarded to",
		describe: func(s Settings) string { return orDefault(s.BackendURL, "(unset: nothing is forwarded)") },
		apply: func(s *Settings, value string) error {
			if value == "" {
				s.BackendURL = ""

				return nil
			}

			// Parsed here so a URL with a path - which would be prepended to
			// the path the rules matched - is refused at `config set` rather
			// than on the first forward leg.
			parsed, err := parseBackendURL(value)
			if err != nil {
				return err
			}

			s.BackendURL = parsed

			return nil
		},
	},
	SettingTokenLifetime: {
		help:     "how long an issued access token is valid",
		describe: func(s Settings) string { return s.TokenLifetime.String() },
		apply: func(s *Settings, value string) error {
			return applyDuration(value, &s.TokenLifetime, false)
		},
	},
	SettingDefaultRateCapacity: {
		help:     "burst size for a client with no limit of its own; 0 is unlimited",
		describe: func(s Settings) string { return strconv.Itoa(s.DefaultRateLimit.Capacity) },
		apply: func(s *Settings, value string) error {
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return fmt.Errorf("must be a non-negative whole number, got %q", value)
			}

			s.DefaultRateLimit.Capacity = parsed

			return nil
		},
	},
	SettingDefaultRatePerSecond: {
		help:     "sustained requests per second for a client with no limit of its own",
		describe: func(s Settings) string { return strconv.FormatFloat(s.DefaultRateLimit.PerSecond, 'g', -1, 64) },
		apply: func(s *Settings, value string) error {
			parsed, err := strconv.ParseFloat(value, 64)
			if err != nil || parsed < 0 {
				return fmt.Errorf("must be a non-negative number, got %q", value)
			}

			s.DefaultRateLimit.PerSecond = parsed

			return nil
		},
	},
	SettingBackendConcurrency: {
		help:     "simultaneous backend calls per replica; 0 is unlimited, and it multiplies by replica count",
		describe: func(s Settings) string { return strconv.Itoa(s.BackendConcurrency) },
		apply: func(s *Settings, value string) error {
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 0 {
				return fmt.Errorf("must be a non-negative whole number, got %q", value)
			}

			s.BackendConcurrency = parsed

			return nil
		},
	},
	SettingCoalesce: {
		help:     "make identical concurrent requests share one backend call",
		describe: func(s Settings) string { return strconv.FormatBool(s.Coalesce) },
		apply:    func(s *Settings, value string) error { return applyBool(value, &s.Coalesce) },
	},
	SettingAuditRetention: {
		help:     "how long pivot keeps its own audit records (GDPR-relevant)",
		describe: func(s Settings) string { return s.AuditRetention.String() },
		apply: func(s *Settings, value string) error {
			return applyDuration(value, &s.AuditRetention, true)
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
	SettingNotifyDedupWindow: {
		help: "window within which identical events are collapsed; 0 delivers every one",
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

// orDefault renders an empty string as a placeholder.
func orDefault(value, placeholder string) string {
	if value == "" {
		return placeholder
	}

	return value
}

// applyDuration parses a duration setting.
func applyDuration(value string, target *time.Duration, allowZero bool) error {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("must be a duration such as 10m or 90d-worth like 2160h, got %q", value)
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

// Get returns one setting's value, rendered for display.
func (s Settings) Get(name string) (string, error) {
	spec, ok := settingSpecs[name]
	if !ok {
		return "", unknownSetting(name)
	}

	return spec.describe(s), nil
}

// Set applies a new value, returning the updated Settings without mutating the
// receiver - so a rejected value leaves nothing half-applied.
func (s Settings) Set(name, value string) (Settings, error) {
	spec, ok := settingSpecs[name]
	if !ok {
		return s, unknownSetting(name)
	}

	updated := s
	if err := spec.apply(&updated, value); err != nil {
		return s, fmt.Errorf("setting %s: %w", name, err)
	}

	if err := updated.Validate(); err != nil {
		return s, err
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

// NewSettingsStore returns the settings repository.
func NewSettingsStore(store kv.Handle) *SettingsStore { return &SettingsStore{store: store} }

// Load returns the stored settings, or the defaults when none have been saved.
func (s *SettingsStore) Load(ctx context.Context) (Settings, error) {
	raw, err := s.store.Get(ctx, settingsKey)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return DefaultSettings(), nil
		}

		return Settings{}, fmt.Errorf("app: read settings: %w", err)
	}

	// Decoded over the defaults, so a document written by an older version
	// that lacks a field gets that field's default rather than its zero value
	// - which for Coalesce would silently turn coalescing off, and for
	// AuditRetention would mean keeping records forever.
	settings := DefaultSettings()
	if err := json.Unmarshal(raw, &settings); err != nil {
		return Settings{}, fmt.Errorf("app: decode settings: %w", err)
	}

	return settings, nil
}

// Save stores the settings.
func (s *SettingsStore) Save(ctx context.Context, settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}

	encoded, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("app: encode settings: %w", err)
	}

	if err := s.store.Set(ctx, settingsKey, encoded); err != nil {
		return fmt.Errorf("app: store settings: %w", err)
	}

	return nil
}

// parseBackendURL validates a backend origin and returns it normalised.
//
// It delegates to config.ParseBackendURL so one rule governs the URL whether
// it arrives as a setting or as a flag: path matching depends on the forwarded path being
// exactly the normalized one, and a base URL carrying a path of its own would
// prepend to a path the rules never saw.
func parseBackendURL(value string) (string, error) {
	parsed, err := config.ParseBackendURL(value)
	if err != nil {
		return "", err
	}

	return parsed.String(), nil
}
