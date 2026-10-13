// Package config is protean's bootstrap configuration: the values that must be
// known before the database can be opened.
//
// # Two layers, deliberately
//
// Bootstrap configuration lives here and comes from flags and the environment.
// Runtime settings - retention periods, rate limits, the log level - live in
// the encrypted database and are managed with `protean config get|set|list`
// over the admin socket.
//
// The split is forced rather than chosen: the database path, the socket path
// and the secret cannot come from the database, because they are what is needed
// to open it. Everything that *can* live in the database does, so that changing
// it does not require a restart or a deployment.
//
// # No configuration file, for now
//
// Flags and environment variables only, which needs nothing outside the
// standard library. protean is a single binary deployed under systemd or in a
// container, where both are the native mechanisms - and the secret already
// arrives that way. Adding a file loader later is one more source feeding the
// same struct, not a rework, so nothing here forecloses it.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adnoctem/netory/pkg/log"
)

// EnvPrefix prefixes every environment variable protean reads.
const EnvPrefix = "PROTEAN_"

// SecretEnv is the environment variable holding the service secret. It is read
// separately from the rest of the configuration, because it is the one value
// that must never be echoed back - not into a log line, not into `config list`.
const SecretEnv = EnvPrefix + "SECRET"

// SecretFileEnv names a file containing the secret, which is how systemd
// credentials and container secrets deliver one. A file is preferable to an
// environment variable: /proc/<pid>/environ is readable by the process owner
// and environment variables are inherited by children.
const SecretFileEnv = EnvPrefix + "SECRET_FILE"

// Defaults for the bootstrap values.
const (
	// DefaultListen is the update API address. It binds all interfaces because
	// dynDNS clients are remote by definition; the admin API is the one that
	// is local-only.
	DefaultListen = ":8443"

	// DefaultSocket is the admin socket path. Under /run because it is
	// ephemeral state that should not survive a reboot - a leftover socket
	// file looks like a running server.
	DefaultSocket = "/run/protean/admin.sock"

	// DefaultDatabase is the Badger directory.
	DefaultDatabase = "/var/lib/protean/db"

	// DefaultShutdownGrace bounds how long a shutdown waits for in-flight
	// requests before dropping them.
	DefaultShutdownGrace = 15 * time.Second
)

// TLS is the native-TLS half of the listener configuration.
type TLS struct {
	// CertFile and KeyFile enable native TLS. Both or neither.
	CertFile string
	KeyFile  string
}

// Enabled reports whether native TLS is configured.
func (t TLS) Enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

// Config is protean's bootstrap configuration.
type Config struct {
	// Listen is the update API address.
	Listen string

	// TLS configures native termination. When unset, protean serves plain
	// HTTP and expects a reverse proxy in front.
	TLS TLS

	// TrustedProxies are the networks whose X-Forwarded-For and
	// X-Forwarded-Proto headers are honoured.
	//
	// There is deliberately no default. In reverse-proxy mode this list is the
	// only thing standing between a client and choosing its own apparent
	// source address, which feeds the per-source rate limiter and the address
	// written to DNS when myip is absent. An empty list means the headers are
	// never consulted, which is the safe failure.
	TrustedProxies []netip.Prefix

	// Socket is the admin socket path.
	Socket string

	// Database is the Badger directory.
	Database string

	// LogLevel and LogFormat configure the logger. The level can also be
	// changed at runtime through the admin API.
	LogLevel  slog.Level
	LogFormat log.Format

	// ShutdownGrace bounds a graceful shutdown.
	ShutdownGrace time.Duration
}

// Default returns the configuration with no sources applied.
func Default() Config {
	return Config{
		Listen:        DefaultListen,
		Socket:        DefaultSocket,
		Database:      DefaultDatabase,
		LogLevel:      slog.LevelInfo,
		LogFormat:     log.FormatText,
		ShutdownGrace: DefaultShutdownGrace,
	}
}

// Validate reports whether the configuration is usable.
func (c Config) Validate() error {
	if c.Listen == "" {
		return errors.New("config: a listen address is required")
	}

	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("config: listen address %q is not host:port: %w", c.Listen, err)
	}

	// Both or neither: a certificate without a key is a configuration that
	// looks like it enables TLS and does not.
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return fmt.Errorf(
			"config: TLS needs both a certificate and a key, got cert=%q key=%q",
			c.TLS.CertFile, c.TLS.KeyFile,
		)
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

	if c.Database == "" {
		return errors.New("config: a database path is required")
	}

	if c.ShutdownGrace < 0 {
		return fmt.Errorf("config: shutdown grace must not be negative, got %s", c.ShutdownGrace)
	}

	return nil
}

// ProxyMode reports whether protean is behind a reverse proxy, which is to say
// not terminating TLS itself.
func (c Config) ProxyMode() bool { return !c.TLS.Enabled() }

// Redacted renders the configuration for `config list` and for a startup log
// line. The secret is not part of Config at all, so there is nothing here to
// leak - which is the reason it is not part of Config.
func (c Config) Redacted() map[string]string {
	proxies := make([]string, 0, len(c.TrustedProxies))
	for _, prefix := range c.TrustedProxies {
		proxies = append(proxies, prefix.String())
	}

	out := map[string]string{
		"listen":          c.Listen,
		"socket":          c.Socket,
		"database":        c.Database,
		"log.level":       c.LogLevel.String(),
		"log.format":      string(c.LogFormat),
		"shutdown.grace":  c.ShutdownGrace.String(),
		"tls":             "disabled (expecting a reverse proxy)",
		"trusted_proxies": strings.Join(proxies, ", "),
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

// ParseTrustedProxies parses a comma-separated list of CIDR prefixes or bare
// addresses.
//
// A bare address is accepted and widened to a single-host prefix, because
// "127.0.0.1" is what an operator will write and demanding "/32" would be
// pedantry with a footgun attached: getting it wrong means the proxy is not
// trusted and every client appears to come from the proxy.
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
			// Masked, so that "10.0.0.5/8" does not silently behave as
			// 10.0.0.0/8 in some comparisons and not others.
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

// env reads a prefixed environment variable.
func env(name string) string { return strings.TrimSpace(os.Getenv(EnvPrefix + name)) }

// ApplyEnv overlays the environment onto c. Flags are applied after, so a flag
// beats an environment variable - the usual precedence, and the one an operator
// debugging a container will expect.
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

	if value := env("DATABASE"); value != "" {
		c.Database = value
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

// ReadSecret returns the raw service secret from the environment.
//
// PROTEAN_SECRET_FILE wins over PROTEAN_SECRET: a deployment that sets both is
// almost certainly migrating towards the file, and the file is the better
// mechanism - an environment variable is visible in /proc/<pid>/environ and is
// inherited by every child process.
//
// The value is returned as a string for pkg/secret to validate. It is never
// logged, and Config does not hold it, so no struct dump can carry it.
func ReadSecret() (string, error) {
	if path := os.Getenv(SecretFileEnv); strings.TrimSpace(path) != "" {
		raw, err := os.ReadFile(strings.TrimSpace(path))
		if err != nil {
			return "", fmt.Errorf("config: read %s=%q: %w", SecretFileEnv, path, err)
		}

		// Trimmed because a file written with a trailing newline is the normal
		// case, and a secret that differs by one byte from the one used to
		// encrypt the database makes it unreadable.
		return strings.TrimSpace(string(raw)), nil
	}

	if raw := os.Getenv(SecretEnv); raw != "" {
		return strings.TrimSpace(raw), nil
	}

	return "", fmt.Errorf(
		"config: no secret found: set %s or %s. Generate one with `protean secret generate`",
		SecretEnv, SecretFileEnv,
	)
}

// IsTrustedProxy reports whether addr is inside the trusted set.
func (c Config) IsTrustedProxy(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	// An IPv4-mapped IPv6 address must be compared as IPv4, or a proxy
	// configured as 10.0.0.0/8 would not match a connection Go reports as:
	// :ffff:10.0.0.1.
	addr = addr.Unmap()

	for _, prefix := range c.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}
