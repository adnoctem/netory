// Package config is pivot's bootstrap configuration: the values that must be
// known before Valkey can be reached.
//
// The same two-layer split as protean's and signpost's, with one difference
// that matters. Their bootstrap layer exists because the database cannot hold
// the values needed to open it; pivot's exists for that reason and because
// pivot runs as several replicas, so the address of the shared store and the
// identity of this replica cannot come from the shared store either.
//
// Everything else lives in Valkey and is managed with `pivot config get|set`,
// which is what makes a change made through one replica apply to all.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/adnoctem/netory/pkg/log"
)

// EnvPrefix prefixes every environment variable pivot reads.
const EnvPrefix = "PIVOT_"

// SecretEnv and SecretFileEnv deliver the service secret. The file is
// preferable: /proc/<pid>/environ is readable by the process owner and
// environment variables are inherited by children.
//
// Every replica must be given the same secret. Keys derived from it decrypt
// the backend credentials in Valkey, so a replica with a different secret
// starts cleanly and then fails every forward leg.
const (
	SecretEnv     = EnvPrefix + "SECRET"
	SecretFileEnv = EnvPrefix + "SECRET_FILE"
)

// ValkeyPasswordFileEnv delivers the Valkey password from a file, for the same
// reason the service secret has one.
const ValkeyPasswordFileEnv = EnvPrefix + "VALKEY_PASSWORD_FILE"

// Defaults for the bootstrap values.
const (
	// DefaultListen is the proxy address. It binds all interfaces: customer
	// traffic is the point.
	DefaultListen = ":8443"

	// DefaultSocket is the admin socket path. One per replica, since the
	// socket is how the CLI reaches *this* process.
	DefaultSocket = "/run/pivot/admin.sock"

	// DefaultValkeyAddress is where a local Valkey listens.
	DefaultValkeyAddress = "127.0.0.1:6379"

	// DefaultShutdownGrace bounds a graceful shutdown. Longer than its
	// siblings': a proxied request is waiting on a backend pivot does not
	// control, and cutting it off turns somebody else's slow response into
	// pivot's failed one.
	DefaultShutdownGrace = 30 * time.Second

	// DefaultBackendTimeout bounds one forward leg.
	DefaultBackendTimeout = 30 * time.Second
)

// TLS is the native-TLS half of the listener configuration.
type TLS struct {
	CertFile string
	KeyFile  string
}

// Enabled reports whether native TLS is configured.
func (t TLS) Enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

// Valkey is the connection to the shared store.
type Valkey struct {
	// Address is one or more nodes as host:port.
	Address []string

	// Username and Password authenticate the connection.
	Username string
	Password string

	// DB selects a logical database. Ignored by a cluster.
	DB int

	// TLS enables TLS to Valkey.
	TLS bool

	// TLSSkipVerify disables certificate verification. It exists because a
	// self-signed Valkey certificate on an internal network is common, and
	// refusing to offer the option would mean operators disabling TLS
	// altogether - which is strictly worse than an unverified encrypted hop.
	TLSSkipVerify bool

	// TLSServerName overrides the name verified against the certificate.
	TLSServerName string
}

// TLSConfig renders the Valkey TLS settings, or nil when TLS is off.
func (v Valkey) TLSConfig() *tls.Config {
	if !v.TLS {
		return nil
	}

	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: v.TLSSkipVerify, //nolint:gosec // operator's explicit choice, see the field
		ServerName:         v.TLSServerName,
	}
}

// Config is pivot's bootstrap configuration.
type Config struct {
	// Listen is the proxy address.
	Listen string

	// TLS configures native termination. Unset means plain HTTP behind a
	// reverse proxy, which on Kubernetes is the ingress and is the expected
	// deployment.
	TLS TLS

	// TrustedProxies are the networks whose X-Forwarded-* headers are
	// honoured.
	//
	// It matters more here than in either sibling. The resolved client
	// address feeds the audit log and the auth-failure events, so an
	// over-broad list lets a customer choose its own apparent source address
	// - and in proxy mode it is also the only evidence that the hop was
	// encrypted.
	TrustedProxies []netip.Prefix

	// Socket is this replica's admin socket path.
	Socket string

	// Valkey is the shared store.
	Valkey Valkey

	// Replica identifies this process in outbox claims and audit records.
	//
	// Defaults to the hostname, which on Kubernetes is the pod name and so is
	// already the identifier an operator would use to find it. It has to be
	// distinct per replica: two replicas sharing an identity could each
	// believe it holds the other's outbox claim.
	Replica string

	// BackendTimeout bounds one forward leg.
	BackendTimeout time.Duration

	// LogLevel and LogFormat configure the logger.
	LogLevel  slog.Level
	LogFormat log.Format

	// ShutdownGrace bounds a graceful shutdown.
	ShutdownGrace time.Duration
}

// Default returns the configuration with no sources applied.
func Default() Config {
	return Config{
		Listen:         DefaultListen,
		Socket:         DefaultSocket,
		Valkey:         Valkey{Address: []string{DefaultValkeyAddress}},
		Replica:        defaultReplica(),
		BackendTimeout: DefaultBackendTimeout,
		LogLevel:       slog.LevelInfo,
		LogFormat:      log.FormatText,
		ShutdownGrace:  DefaultShutdownGrace,
	}
}

// defaultReplica returns the hostname, or a clearly artificial placeholder
// when it cannot be read.
//
// The placeholder is deliberately not something that looks like a real name:
// an outbox claim held by "unknown-replica" is a configuration problem an
// operator should be able to spot in a log line.
func defaultReplica() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "unknown-replica"
	}

	return name
}

// Validate reports whether the configuration is usable.
func (c Config) Validate() error {
	if c.Listen == "" {
		return errors.New("config: a listen address is required")
	}

	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("config: listen address %q is not host:port: %w", c.Listen, err)
	}

	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return fmt.Errorf(
			"config: TLS needs both a certificate and a key, got cert=%q key=%q",
			c.TLS.CertFile, c.TLS.KeyFile)
	}

	if c.TLS.Enabled() {
		for name, path := range map[string]string{"certificate": c.TLS.CertFile, "key": c.TLS.KeyFile} {
			if _, err := os.Stat(path); err != nil {
				return fmt.Errorf("config: TLS %s %q is not readable: %w", name, path, err)
			}
		}
	}

	if c.Socket == "" {
		return errors.New("config: an admin socket path is required")
	}

	if !filepath.IsAbs(c.Socket) {
		return fmt.Errorf("config: admin socket path %q must be absolute", c.Socket)
	}

	if len(c.Valkey.Address) == 0 {
		return errors.New("config: at least one Valkey address is required")
	}

	for i, addr := range c.Valkey.Address {
		if strings.TrimSpace(addr) == "" {
			return fmt.Errorf("config: Valkey address %d is empty", i)
		}

		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("config: Valkey address %q is not host:port: %w", addr, err)
		}
	}

	if strings.TrimSpace(c.Replica) == "" {
		return errors.New("config: a replica identifier is required")
	}

	if c.BackendTimeout <= 0 {
		return fmt.Errorf("config: the backend timeout must be positive, got %s", c.BackendTimeout)
	}

	if c.ShutdownGrace < 0 {
		return fmt.Errorf("config: shutdown grace must not be negative, got %s", c.ShutdownGrace)
	}

	return nil
}

// ProxyMode reports whether pivot is behind a reverse proxy.
func (c Config) ProxyMode() bool { return !c.TLS.Enabled() }

// Redacted renders the configuration for `config view` and the startup log.
//
// The Valkey password is the one bootstrap value that is a credential, so it
// is reported as set or unset and never shown. The service secret is not part
// of Config at all.
func (c Config) Redacted() map[string]string {
	proxies := make([]string, 0, len(c.TrustedProxies))
	for _, prefix := range c.TrustedProxies {
		proxies = append(proxies, prefix.String())
	}

	out := map[string]string{
		"listen":          c.Listen,
		"socket":          c.Socket,
		"replica":         c.Replica,
		"valkey.address":  strings.Join(c.Valkey.Address, ", "),
		"valkey.db":       strconv.Itoa(c.Valkey.DB),
		"valkey.tls":      strconv.FormatBool(c.Valkey.TLS),
		"valkey.username": dashed(c.Valkey.Username),
		"valkey.password": setOrUnset(c.Valkey.Password),
		"backend.timeout": c.BackendTimeout.String(),
		"log.level":       c.LogLevel.String(),
		"log.format":      string(c.LogFormat),
		"shutdown.grace":  c.ShutdownGrace.String(),
		"tls":             "disabled (expecting a reverse proxy)",
		"trusted_proxies": strings.Join(proxies, ", "),
	}

	if c.Valkey.TLS && c.Valkey.TLSSkipVerify {
		out["valkey.tls"] = "true (certificate verification disabled)"
	}

	if c.TLS.Enabled() {
		out["tls"] = "enabled"
		out["tls.cert"] = c.TLS.CertFile
		out["tls.key"] = c.TLS.KeyFile
	}

	if len(proxies) == 0 {
		out["trusted_proxies"] = "none (X-Forwarded-* headers are ignored)"
	}

	return out
}

// setOrUnset reports whether a credential is configured without showing it.
func setOrUnset(value string) string {
	if value == "" {
		return "(unset)"
	}

	return "(set)"
}

// dashed renders an empty string as a dash.
func dashed(value string) string {
	if value == "" {
		return "-"
	}

	return value
}

// ParseTrustedProxies parses a comma-separated list of CIDR prefixes or bare
// addresses. A bare address is widened to a single host, because "10.0.0.5" is
// what an operator will write.
func ParseTrustedProxies(raw string) ([]netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var prefixes []netip.Prefix

	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if prefix, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, prefix.Masked())

			continue
		}

		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("config: %q is not an IP address or CIDR prefix", entry)
		}

		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return prefixes, nil
}

// ParseBackendURL validates a backend base URL.
//
// Checked here rather than at the first forward leg: a backend URL with a
// path, a query or a fragment would make the forwarded path ambiguous, and
// "pivot and the backend's router see the same request" depends on the
// forwarded path being exactly the normalized one.
func ParseBackendURL(raw string) (*url.URL, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("config: a backend URL is required")
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("config: backend URL %q is not a URL: %w", raw, err)
	}

	switch parsed.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf(
			"config: backend URL %q must be http or https, got scheme %q", raw, parsed.Scheme)
	}

	if parsed.Host == "" {
		return nil, fmt.Errorf("config: backend URL %q has no host", raw)
	}

	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf(
			"config: backend URL %q must carry no query or fragment: pivot forwards the "+
				"normalized request path unchanged, and a base URL that adds to it would make "+
				"the forwarded path differ from the one the rules matched", raw)
	}

	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf(
			"config: backend URL %q must carry no path, got %q: pivot forwards the normalized "+
				"request path unchanged, so a base path would be prepended to a path the rules "+
				"never saw", raw, parsed.Path)
	}

	// Normalised to scheme://host so the forward leg can concatenate without
	// worrying about a trailing slash.
	return &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}, nil
}

// env reads a prefixed environment variable.
func env(name string) string { return strings.TrimSpace(os.Getenv(EnvPrefix + name)) }

// ApplyEnv overlays the environment onto c. Flags are applied afterwards, so a
// flag beats an environment variable.
func (c *Config) ApplyEnv() error {
	if value := env("LISTEN"); value != "" {
		c.Listen = value
	}

	if value := env("TLS_CERT"); value != "" {
		c.TLS.CertFile = value
	}

	if value := env("TLS_KEY"); value != "" {
		c.TLS.KeyFile = value
	}

	if value := env("TRUSTED_PROXIES"); value != "" {
		prefixes, err := ParseTrustedProxies(value)
		if err != nil {
			return fmt.Errorf("%sTRUSTED_PROXIES: %w", EnvPrefix, err)
		}

		c.TrustedProxies = prefixes
	}

	if value := env("SOCKET"); value != "" {
		c.Socket = value
	}

	if value := env("REPLICA"); value != "" {
		c.Replica = value
	}

	if value := env("VALKEY_ADDRESS"); value != "" {
		c.Valkey.Address = splitList(value)
	}

	if value := env("VALKEY_USERNAME"); value != "" {
		c.Valkey.Username = value
	}

	password, err := readValkeyPassword()
	if err != nil {
		return err
	}

	if password != "" {
		c.Valkey.Password = password
	}

	if value := env("VALKEY_DB"); value != "" {
		db, err := strconv.Atoi(value)
		if err != nil || db < 0 {
			return fmt.Errorf("%sVALKEY_DB: %q is not a non-negative integer", EnvPrefix, value)
		}

		c.Valkey.DB = db
	}

	if value := env("VALKEY_TLS"); value != "" {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%sVALKEY_TLS: %q is not a boolean", EnvPrefix, value)
		}

		c.Valkey.TLS = enabled
	}

	if value := env("VALKEY_TLS_SKIP_VERIFY"); value != "" {
		skip, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("%sVALKEY_TLS_SKIP_VERIFY: %q is not a boolean", EnvPrefix, value)
		}

		c.Valkey.TLSSkipVerify = skip
	}

	if value := env("VALKEY_TLS_SERVER_NAME"); value != "" {
		c.Valkey.TLSServerName = value
	}

	if value := env("BACKEND_TIMEOUT"); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("%sBACKEND_TIMEOUT: %q is not a duration: %w", EnvPrefix, value, err)
		}

		c.BackendTimeout = timeout
	}

	if value := env("LOG_LEVEL"); value != "" {
		level, ok := log.ParseLevel(value)
		if !ok {
			return fmt.Errorf("%sLOG_LEVEL: %q is not one of debug, info, warn, error", EnvPrefix, value)
		}

		c.LogLevel = level
	}

	if value := env("LOG_FORMAT"); value != "" {
		format, ok := log.ParseFormat(value)
		if !ok {
			return fmt.Errorf("%sLOG_FORMAT: %q is not one of text, json", EnvPrefix, value)
		}

		c.LogFormat = format
	}

	if value := env("SHUTDOWN_GRACE"); value != "" {
		grace, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("%sSHUTDOWN_GRACE: %q is not a duration: %w", EnvPrefix, value, err)
		}

		c.ShutdownGrace = grace
	}

	return nil
}

// readValkeyPassword returns the Valkey password from a file or the
// environment, preferring the file.
func readValkeyPassword() (string, error) {
	if path := strings.TrimSpace(os.Getenv(ValkeyPasswordFileEnv)); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("config: read %s=%q: %w", ValkeyPasswordFileEnv, path, err)
		}

		return strings.TrimSpace(string(raw)), nil
	}

	return env("VALKEY_PASSWORD"), nil
}

// splitList parses a comma-separated list, dropping empty entries.
func splitList(raw string) []string {
	var out []string

	for _, entry := range strings.Split(raw, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, entry)
		}
	}

	return out
}

// ReadSecret returns the raw service secret from the environment.
func ReadSecret() (string, error) {
	if path := os.Getenv(SecretFileEnv); strings.TrimSpace(path) != "" {
		raw, err := os.ReadFile(strings.TrimSpace(path))
		if err != nil {
			return "", fmt.Errorf("config: read %s=%q: %w", SecretFileEnv, path, err)
		}

		// Trimmed because a secret file written with a trailing newline is the
		// normal case, and every replica must derive the same keys - a secret
		// differing by one byte makes one replica unable to decrypt what the
		// others wrote.
		return strings.TrimSpace(string(raw)), nil
	}

	if raw := os.Getenv(SecretEnv); raw != "" {
		return strings.TrimSpace(raw), nil
	}

	return "", fmt.Errorf(
		"config: no secret found: set %s or %s. Generate one with `pivot secret generate`, "+
			"and give every replica the same value",
		SecretEnv, SecretFileEnv)
}
