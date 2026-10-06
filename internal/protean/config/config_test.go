package config_test

import (
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/protean/config"
	"github.com/adnoctem/netory/pkg/log"
)

func TestDefaultIsValid(t *testing.T) {
	assert.NoError(t, config.Default().Validate())
}

func TestValidate(t *testing.T) {
	asrt := assert.New(t)

	cfg := config.Default()
	cfg.Listen = ""
	asrt.Error(cfg.Validate(), "a listen address is required")

	cfg = config.Default()
	cfg.Listen = "not-host-port"
	asrt.Error(cfg.Validate())

	cfg = config.Default()
	cfg.Socket = "relative/path.sock"
	asrt.Error(cfg.Validate(), "the socket path must be absolute")

	cfg = config.Default()
	cfg.Database = ""
	asrt.Error(cfg.Validate())

	cfg = config.Default()
	cfg.ShutdownGrace = -time.Second
	asrt.Error(cfg.Validate())
}

// A certificate without a key is a configuration that looks like it enables
// TLS and does not.
func TestValidateRejectsHalfConfiguredTLS(t *testing.T) {
	asrt := assert.New(t)

	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(cert, []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(key, []byte("x"), 0o600))

	cfg := config.Default()
	cfg.TLS.CertFile = cert
	asrt.Error(cfg.Validate(), "a certificate without a key must be refused")

	cfg = config.Default()
	cfg.TLS.KeyFile = key
	asrt.Error(cfg.Validate(), "a key without a certificate must be refused")

	cfg = config.Default()
	cfg.TLS.CertFile, cfg.TLS.KeyFile = cert, key
	asrt.NoError(cfg.Validate())
	asrt.True(cfg.TLS.Enabled())
	asrt.False(cfg.ProxyMode())

	// An unreadable file is caught at startup rather than on the first
	// connection, which would be a TLS handshake failure with no explanation.
	cfg.TLS.CertFile = filepath.Join(dir, "absent.pem")
	asrt.Error(cfg.Validate())
}

func TestApplyEnv(t *testing.T) {
	asrt := assert.New(t)

	for key, value := range map[string]string{
		"PROTEAN_LISTEN":          ":9443",
		"PROTEAN_SOCKET":          "/run/custom/a.sock",
		"PROTEAN_DATABASE":        "/var/lib/custom",
		"PROTEAN_TRUSTED_PROXIES": "10.0.0.0/8,127.0.0.1",
		"PROTEAN_LOG_LEVEL":       "debug",
		"PROTEAN_LOG_FORMAT":      "json",
		"PROTEAN_SHUTDOWN_GRACE":  "45s",
	} {
		t.Setenv(key, value)
	}

	cfg := config.Default()
	require.NoError(t, cfg.ApplyEnv())

	asrt.Equal(":9443", cfg.Listen)
	asrt.Equal("/run/custom/a.sock", cfg.Socket)
	asrt.Equal("/var/lib/custom", cfg.Database)
	asrt.Equal(slog.LevelDebug, cfg.LogLevel)
	asrt.Equal(log.FormatJSON, cfg.LogFormat)
	asrt.Equal(45*time.Second, cfg.ShutdownGrace)
	require.Len(t, cfg.TrustedProxies, 2)
	asrt.Equal("10.0.0.0/8", cfg.TrustedProxies[0].String())
}

func TestApplyEnvRejectsBadValues(t *testing.T) {
	asrt := assert.New(t)

	for key, value := range map[string]string{
		"PROTEAN_LOG_LEVEL":       "chatty",
		"PROTEAN_LOG_FORMAT":      "xml",
		"PROTEAN_SHUTDOWN_GRACE":  "soon",
		"PROTEAN_TRUSTED_PROXIES": "nonsense",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)

			cfg := config.Default()
			err := cfg.ApplyEnv()
			asrt.Error(err, "%s=%s", key, value)
			asrt.Contains(err.Error(), key, "the error must name the variable")
		})
	}
}

// trusted_proxies has no default, and an empty list means the forwarding
// headers are never consulted - which is the safe failure.
func TestIsTrustedProxy(t *testing.T) {
	asrt := assert.New(t)

	cfg := config.Default()
	asrt.Empty(cfg.TrustedProxies, "there is deliberately no default trusted set")
	asrt.False(cfg.IsTrustedProxy(netip.MustParseAddr("10.0.0.1")))

	prefixes, err := config.ParseTrustedProxies("10.0.0.0/8, 2001:db8::/32")
	require.NoError(t, err)
	cfg.TrustedProxies = prefixes

	asrt.True(cfg.IsTrustedProxy(netip.MustParseAddr("10.1.2.3")))
	asrt.True(cfg.IsTrustedProxy(netip.MustParseAddr("2001:db8::1")))
	asrt.False(cfg.IsTrustedProxy(netip.MustParseAddr("203.0.113.1")))

	// An IPv4-mapped IPv6 address must match an IPv4 prefix, or a proxy
	// configured as 10.0.0.0/8 would not match a connection Go reports as
	// ::ffff:10.0.0.1.
	asrt.True(cfg.IsTrustedProxy(netip.MustParseAddr("::ffff:10.0.0.1")))

	asrt.False(cfg.IsTrustedProxy(netip.Addr{}), "the zero address is never trusted")
}

// The secret is never part of Config, so no struct dump can carry it.
func TestRedactedCarriesNoSecret(t *testing.T) {
	asrt := assert.New(t)

	t.Setenv(config.SecretEnv, "a-secret-that-must-not-appear-anywhere")

	cfg := config.Default()
	require.NoError(t, cfg.ApplyEnv())

	for key, value := range cfg.Redacted() {
		asrt.NotContains(value, "must-not-appear", "the secret leaked through %q", key)
	}

	// And the proxy-mode warning is visible in the rendered configuration, so
	// an operator reading the startup log sees it.
	asrt.Contains(cfg.Redacted()["trusted_proxies"], "ignored")
	asrt.Contains(cfg.Redacted()["tls"], "reverse proxy")
}

// A file is preferable to an environment variable: /proc/<pid>/environ is
// readable by the process owner and environment variables are inherited by
// children. So the file wins when both are set.
func TestReadSecretPrefersTheFile(t *testing.T) {
	asrt := assert.New(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "secret")

	// With a trailing newline, which is how a file written by `secret
	// generate >` or by a secret manager actually looks. A secret differing by
	// one byte makes the database unreadable.
	require.NoError(t, os.WriteFile(path, []byte("from-the-file\n"), 0o600))

	t.Setenv(config.SecretEnv, "from-the-environment")
	t.Setenv(config.SecretFileEnv, path)

	got, err := config.ReadSecret()
	asrt.NoError(err)
	asrt.Equal("from-the-file", got, "the file wins, and its trailing newline is trimmed")
}

func TestReadSecretFromEnvironment(t *testing.T) {
	asrt := assert.New(t)

	t.Setenv(config.SecretEnv, "  from-the-environment  ")

	got, err := config.ReadSecret()
	asrt.NoError(err)
	asrt.Equal("from-the-environment", got)
}

func TestReadSecretReportsItsAbsenceUsefully(t *testing.T) {
	asrt := assert.New(t)

	t.Setenv(config.SecretEnv, "")
	t.Setenv(config.SecretFileEnv, "")

	_, err := config.ReadSecret()
	asrt.Error(err)
	asrt.Contains(err.Error(), config.SecretEnv)
	asrt.Contains(err.Error(), config.SecretFileEnv)
	asrt.Contains(err.Error(), "secret generate", "the error must say how to produce one")

	// A named file that does not exist is an error, not a silent fallback to
	// the environment variable: the operator asked for that file.
	t.Setenv(config.SecretEnv, "from-the-environment")
	t.Setenv(config.SecretFileEnv, filepath.Join(t.TempDir(), "absent"))

	_, err = config.ReadSecret()
	asrt.Error(err)
	asrt.Contains(err.Error(), config.SecretFileEnv)
}

func TestSocketPathIsWithinTheKernelLimit(t *testing.T) {
	// The default socket path has to be bindable, or a fresh install fails
	// with an error about path length before doing anything useful.
	assert.LessOrEqual(t, len(config.DefaultSocket), 100,
		"the default socket path must leave room under the 108-byte sockaddr_un limit")
	assert.True(t, strings.HasPrefix(config.DefaultSocket, "/run/"),
		"the socket belongs in /run: it is ephemeral, and a leftover file looks like a running server")
}
