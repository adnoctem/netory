package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/config"
)

func TestDefaultIsValid(t *testing.T) {
	t.Parallel()

	assert.NoError(t, config.Default().Validate())
}

func TestValidate(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*config.Config){
		"no listen address":   func(c *config.Config) { c.Listen = "" },
		"listen without port": func(c *config.Config) { c.Listen = "example.org" },
		"cert without key":    func(c *config.Config) { c.TLS.CertFile = "/tmp/cert.pem" },
		"key without cert":    func(c *config.Config) { c.TLS.KeyFile = "/tmp/key.pem" },
		"no socket":           func(c *config.Config) { c.Socket = "" },
		"relative socket":     func(c *config.Config) { c.Socket = "run/admin.sock" },
		"no valkey address":   func(c *config.Config) { c.Valkey.Address = nil },
		"blank valkey":        func(c *config.Config) { c.Valkey.Address = []string{"  "} },
		"valkey without port": func(c *config.Config) { c.Valkey.Address = []string{"valkey"} },
		"no replica":          func(c *config.Config) { c.Replica = "" },
		"zero backend timeout": func(c *config.Config) {
			c.BackendTimeout = 0
		},
		"negative grace": func(c *config.Config) { c.ShutdownGrace = -time.Second },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Default()
			mutate(&cfg)

			assert.Error(t, cfg.Validate())
		})
	}
}

// A backend URL carrying a path would be prepended to the path the rules
// matched, so pivot and the backend's router would see different requests -
// which is the one property normalization exists to protect.
func TestParseBackendURL(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://shop.internal.example",
		"https://shop.internal.example/",
		"http://127.0.0.1:8000",
	} {
		parsed, err := config.ParseBackendURL(raw)
		require.NoError(t, err, raw)
		assert.Empty(t, parsed.Path, "the parsed URL is normalised to scheme://host")
	}

	for name, raw := range map[string]string{
		"empty":           "",
		"no scheme":       "shop.internal.example",
		"bad scheme":      "ftp://shop.internal.example",
		"no host":         "https://",
		"with a path":     "https://shop.internal.example/api",
		"with a query":    "https://shop.internal.example?x=1",
		"with a fragment": "https://shop.internal.example#x",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := config.ParseBackendURL(raw)
			assert.Error(t, err)
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	t.Parallel()

	prefixes, err := config.ParseTrustedProxies("10.0.0.0/8, 192.168.1.5, 2001:db8::/32")
	require.NoError(t, err)
	require.Len(t, prefixes, 3)

	asrt := assert.New(t)
	asrt.Equal("10.0.0.0/8", prefixes[0].String())
	asrt.Equal("192.168.1.5/32", prefixes[1].String(), "a bare address widens to a single host")
	asrt.Equal("2001:db8::/32", prefixes[2].String())

	empty, err := config.ParseTrustedProxies("  ")
	require.NoError(t, err)
	asrt.Empty(empty)

	_, err = config.ParseTrustedProxies("not-an-address")
	asrt.Error(err)
}

// The Valkey password is the one bootstrap value that is a credential, so it
// must never appear in `config view` or the startup log.
func TestRedactedHidesTheValkeyPassword(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Valkey.Password = "a-real-password"
	cfg.Valkey.Username = "pivot"

	redacted := cfg.Redacted()

	asrt := assert.New(t)
	asrt.Equal("(set)", redacted["valkey.password"])
	asrt.Equal("pivot", redacted["valkey.username"], "a username is not a secret")

	for key, value := range redacted {
		asrt.NotContains(value, "a-real-password", "key %q leaked the password", key)
	}

	cfg.Valkey.Password = ""
	asrt.Equal("(unset)", cfg.Redacted()["valkey.password"])
}

func TestRedactedReportsTheTLSMode(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	asrt := assert.New(t)

	asrt.Contains(cfg.Redacted()["tls"], "disabled")
	asrt.True(cfg.ProxyMode())
	asrt.Contains(cfg.Redacted()["trusted_proxies"], "none")

	cfg.TLS = config.TLS{CertFile: "/tmp/cert.pem", KeyFile: "/tmp/key.pem"}
	asrt.Equal("enabled", cfg.Redacted()["tls"])
	asrt.False(cfg.ProxyMode())

	// An unverified TLS connection to Valkey is the operator's choice, and the
	// startup log says so rather than reporting TLS as simply on.
	cfg.Valkey.TLS = true
	cfg.Valkey.TLSSkipVerify = true
	asrt.Contains(cfg.Redacted()["valkey.tls"], "verification disabled")
}

func TestApplyEnv(t *testing.T) {
	t.Setenv("PIVOT_LISTEN", "127.0.0.1:9000")
	t.Setenv("PIVOT_SOCKET", "/run/custom/admin.sock")
	t.Setenv("PIVOT_REPLICA", "pivot-0")
	t.Setenv("PIVOT_VALKEY_ADDRESS", "valkey-a:6379, valkey-b:6379")
	t.Setenv("PIVOT_VALKEY_USERNAME", "pivot")
	t.Setenv("PIVOT_VALKEY_PASSWORD", "secret")
	t.Setenv("PIVOT_VALKEY_DB", "3")
	t.Setenv("PIVOT_VALKEY_TLS", "true")
	t.Setenv("PIVOT_TRUSTED_PROXIES", "10.0.0.0/8")
	t.Setenv("PIVOT_BACKEND_TIMEOUT", "45s")
	t.Setenv("PIVOT_LOG_FORMAT", "json")
	t.Setenv("PIVOT_LOG_LEVEL", "debug")
	t.Setenv("PIVOT_SHUTDOWN_GRACE", "1m")

	cfg := config.Default()
	require.NoError(t, cfg.ApplyEnv())

	asrt := assert.New(t)
	asrt.Equal("127.0.0.1:9000", cfg.Listen)
	asrt.Equal("/run/custom/admin.sock", cfg.Socket)
	asrt.Equal("pivot-0", cfg.Replica)
	asrt.Equal([]string{"valkey-a:6379", "valkey-b:6379"}, cfg.Valkey.Address)
	asrt.Equal("pivot", cfg.Valkey.Username)
	asrt.Equal("secret", cfg.Valkey.Password)
	asrt.Equal(3, cfg.Valkey.DB)
	asrt.True(cfg.Valkey.TLS)
	asrt.Len(cfg.TrustedProxies, 1)
	asrt.Equal(45*time.Second, cfg.BackendTimeout)
	asrt.Equal(time.Minute, cfg.ShutdownGrace)
	asrt.NoError(cfg.Validate())

	require.NotNil(t, cfg.Valkey.TLSConfig())
	asrt.False(cfg.Valkey.TLSConfig().InsecureSkipVerify)
}

func TestApplyEnvRejectsMalformedValues(t *testing.T) {
	for name, env := range map[string][2]string{
		"bad db":          {"PIVOT_VALKEY_DB", "-1"},
		"db not a number": {"PIVOT_VALKEY_DB", "many"},
		"bad tls":         {"PIVOT_VALKEY_TLS", "perhaps"},
		"bad proxies":     {"PIVOT_TRUSTED_PROXIES", "not-an-address"},
		"bad timeout":     {"PIVOT_BACKEND_TIMEOUT", "soon"},
		"bad level":       {"PIVOT_LOG_LEVEL", "shout"},
		"bad format":      {"PIVOT_LOG_FORMAT", "yaml"},
		"bad grace":       {"PIVOT_SHUTDOWN_GRACE", "a while"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(env[0], env[1])

			cfg := config.Default()
			assert.Error(t, cfg.ApplyEnv())
		})
	}
}

// A file is preferred over an environment variable for both credentials,
// because /proc/<pid>/environ is readable by the process owner and environment
// variables are inherited by children.
func TestFileBeatsEnvironmentForSecrets(t *testing.T) {
	dir := t.TempDir()

	secretPath := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(secretPath, []byte("from-the-file\n"), 0o600))

	t.Setenv("PIVOT_SECRET", "from-the-environment")
	t.Setenv("PIVOT_SECRET_FILE", secretPath)

	secret, err := config.ReadSecret()
	require.NoError(t, err)
	assert.Equal(t, "from-the-file", secret, "and the trailing newline is trimmed")

	passwordPath := filepath.Join(dir, "valkey-password")
	require.NoError(t, os.WriteFile(passwordPath, []byte("file-password\n"), 0o600))

	t.Setenv("PIVOT_VALKEY_PASSWORD", "env-password")
	t.Setenv("PIVOT_VALKEY_PASSWORD_FILE", passwordPath)

	cfg := config.Default()
	require.NoError(t, cfg.ApplyEnv())
	assert.Equal(t, "file-password", cfg.Valkey.Password)
}

func TestReadSecretReportsWhereToPutOne(t *testing.T) {
	t.Setenv("PIVOT_SECRET", "")
	t.Setenv("PIVOT_SECRET_FILE", "")

	_, err := config.ReadSecret()
	require.Error(t, err)

	// The message has to name both variables and say that every replica needs
	// the same value, since a per-replica secret fails only on the forward leg.
	asrt := assert.New(t)
	asrt.Contains(err.Error(), "PIVOT_SECRET")
	asrt.Contains(err.Error(), "PIVOT_SECRET_FILE")
	asrt.Contains(err.Error(), "every replica")
}

func TestMissingSecretFileIsAnError(t *testing.T) {
	t.Setenv("PIVOT_SECRET_FILE", filepath.Join(t.TempDir(), "absent"))

	_, err := config.ReadSecret()
	assert.Error(t, err)
}
