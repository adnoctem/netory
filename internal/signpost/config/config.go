// Package config is signpost's bootstrap configuration: the values that must
// be known before the database can be opened.
//
// Same two-layer split as protean's, and for the same forced reason - the
// database path, the socket path and the secret cannot come from the database,
// because they are what is needed to open it. Everything that can live in the
// database does, managed with `signpost config get|set|list`.
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

// EnvPrefix prefixes every environment variable signpost reads.
const EnvPrefix = "SIGNPOST_"

// SecretEnv and SecretFileEnv deliver the service secret. The file is
// preferable: /proc/<pid>/environ is readable by the process owner and
// environment variables are inherited by children.
const (
	SecretEnv     = EnvPrefix + "SECRET"
	SecretFileEnv = EnvPrefix + "SECRET_FILE"
)

// Defaults for the bootstrap values.
const (
	// DefaultListen is the public API address. It binds all interfaces:
	// serving scripts to anyone is the entire point.
	DefaultListen = ":8443"

	// DefaultSocket is the admin socket path.
	DefaultSocket = "/run/signpost/admin.sock"

	// DefaultDatabase is the Badger directory.
	DefaultDatabase = "/var/lib/signpost/db"

	// DefaultContent is where script contents live (§5.1).
	DefaultContent = "/var/lib/signpost/content"

	// DefaultShutdownGrace bounds a graceful shutdown.
	DefaultShutdownGrace = 15 * time.Second
)

// TLS is the native-TLS half of the listener configuration.
type TLS struct {
	CertFile string
	KeyFile  string
}

// Enabled reports whether native TLS is configured.
func (t TLS) Enabled() bool { return t.CertFile != "" || t.KeyFile != "" }

// Config is signpost's bootstrap configuration.
type Config struct {
	// Listen is the public API address.
	Listen string

	// TLS configures native termination. Unset means plain HTTP behind a
	// reverse proxy.
	TLS TLS

	// TrustedProxies are the networks whose X-Forwarded-* headers are
	// honoured.
	//
	// It matters more here than it looks. signpost serves anonymously and has
	// no per-source rate limiter, but §9.6 requires it to refuse to serve a
	// script over a connection it cannot confirm was encrypted - and in proxy
	// mode the only evidence is X-Forwarded-Proto from a peer in this list.
	// Without the list, signpost cannot distinguish a proxied HTTPS request
	// from a direct plaintext one.
	TrustedProxies []netip.Prefix

	// Socket is the admin socket path.
	Socket string

	// Database is the Badger directory.
	Database string

	// Content is the directory script contents are stored in.
	Content string

	// LogLevel and LogFormat configure the logger.
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
		Content:       DefaultContent,
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

	if c.Database == "" {
		return errors.New("config: a database path is required")
	}

	if c.Content == "" {
		return errors.New("config: a content path is required")
	}

	// The content tree and the database must not be the same directory:
	// Badger owns its directory and writing release content into it would at
	// best confuse its file accounting.
	if absEqual(c.Database, c.Content) {
		return fmt.Errorf(
			"config: the database and content directories must differ, both are %q", c.Database)
	}

	if c.ShutdownGrace < 0 {
		return fmt.Errorf("config: shutdown grace must not be negative, got %s", c.ShutdownGrace)
	}

	return nil
}

// absEqual reports whether two paths resolve to the same place.
func absEqual(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)

	if errA != nil || errB != nil {
		return a == b
	}

	return filepath.Clean(absA) == filepath.Clean(absB)
}

// ProxyMode reports whether signpost is behind a reverse proxy.
func (c Config) ProxyMode() bool { return !c.TLS.Enabled() }

// Redacted renders the configuration for `config view` and the startup log.
// The secret is not part of Config, so there is nothing here to leak.
func (c Config) Redacted() map[string]string {
	proxies := make([]string, 0, len(c.TrustedProxies))
	for _, prefix := range c.TrustedProxies {
		proxies = append(proxies, prefix.String())
	}

	out := map[string]string{
		"listen":          c.Listen,
		"socket":          c.Socket,
		"database":        c.Database,
		"content":         c.Content,
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
// addresses. A bare address is widened to a single host, because "127.0.0.1"
// is what an operator will write.
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

// IsTrustedProxy reports whether addr is inside the trusted set.
func (c Config) IsTrustedProxy(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}

	// An IPv4-mapped IPv6 address must compare as IPv4, or a proxy configured
	// as 10.0.0.0/8 would not match a connection Go reports as
	// ::ffff:10.0.0.1.
	addr = addr.Unmap()

	for _, prefix := range c.TrustedProxies {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
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

	if value := env("DATABASE"); value != "" {
		c.Database = value
	}

	if value := env("CONTENT"); value != "" {
		c.Content = value
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
// The file wins over the variable when both are set, for the reason given on
// SecretFileEnv. The value is never logged and Config does not hold it.
func ReadSecret() (string, error) {
	if path := os.Getenv(SecretFileEnv); strings.TrimSpace(path) != "" {
		raw, err := os.ReadFile(strings.TrimSpace(path))
		if err != nil {
			return "", fmt.Errorf("config: read %s=%q: %w", SecretFileEnv, path, err)
		}

		// Trimmed because a secret file written with a trailing newline is the
		// normal case, and a secret differing by one byte makes the database
		// unreadable.
		return strings.TrimSpace(string(raw)), nil
	}

	if raw := os.Getenv(SecretEnv); raw != "" {
		return strings.TrimSpace(raw), nil
	}

	return "", fmt.Errorf(
		"config: no secret found: set %s or %s. Generate one with `signpost secret generate`",
		SecretEnv, SecretFileEnv)
}
