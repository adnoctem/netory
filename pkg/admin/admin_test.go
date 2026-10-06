package admin_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/admin"
	"github.com/adnoctem/netory/pkg/log"
)

type hostPayload struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

// harness starts an admin server on a socket in a temp directory and returns a
// client for it, plus the buffer its audit records land in.
type harness struct {
	server *admin.Server
	client *admin.Client
	audit  *syncBuffer
	path   string
}

func newHarness(t *testing.T, handler http.Handler) *harness {
	t.Helper()

	// Short directory names: a Unix socket path is limited to 108 bytes on
	// Linux, and t.TempDir() names are derived from the test name, so a long
	// subtest name plus a long socket name overflows it.
	dir, err := os.MkdirTemp("", "adm")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "s")
	buf := &syncBuffer{}

	srv, err := admin.NewServer(admin.ServerOptions{
		Path:    path,
		Handler: handler,
		Logger:  log.New(log.WithOutput(buf), log.WithLevel(slog.LevelDebug), log.WithFormat(log.FormatJSON)),
	})
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve()
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})

	client, err := admin.NewClient(admin.ClientOptions{Path: path, Timeout: 10 * time.Second})
	require.NoError(t, err)

	return &harness{server: srv, client: client, audit: buf, path: path}
}

func testMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /hosts", func(w http.ResponseWriter, _ *http.Request) {
		admin.WriteJSON(w, http.StatusOK, []hostPayload{{Name: "a.example", Provider: "cloudflare"}})
	})

	mux.HandleFunc("POST /hosts", func(w http.ResponseWriter, r *http.Request) {
		var in hostPayload
		if err := admin.DecodeJSON(w, r, &in); err != nil {
			admin.WriteError(w, err)

			return
		}

		admin.WriteJSON(w, http.StatusCreated, in)
	})

	mux.HandleFunc("DELETE /hosts/{name}", func(w http.ResponseWriter, _ *http.Request) {
		admin.WriteJSON(w, http.StatusNoContent, nil)
	})

	mux.HandleFunc("GET /missing", func(w http.ResponseWriter, _ *http.Request) {
		admin.WriteError(w, admin.Errorf(http.StatusNotFound, "no such host %q", "b.example").
			WithHint("run `protean host list` to see the configured hosts"))
	})

	mux.HandleFunc("GET /boom", func(w http.ResponseWriter, _ *http.Request) {
		admin.WriteError(w, errors.New("the provider credentials file could not be read"))
	})

	mux.HandleFunc("GET /whoami", func(w http.ResponseWriter, r *http.Request) {
		peer, ok := admin.PeerFrom(r.Context())
		admin.WriteJSON(w, http.StatusOK, map[string]any{
			"known":    ok,
			"uid":      peer.UID,
			"pid":      peer.PID,
			"rendered": peer.String(),
		})
	})

	return mux
}

func TestRoundTrip(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, testMux())

	var hosts []hostPayload
	asrt.NoError(h.client.Get(ctx, "/hosts", &hosts))
	asrt.Equal([]hostPayload{{Name: "a.example", Provider: "cloudflare"}}, hosts)

	var created hostPayload
	asrt.NoError(h.client.Post(ctx, "/hosts", hostPayload{Name: "b.example", Provider: "route53"}, &created))
	asrt.Equal(hostPayload{Name: "b.example", Provider: "route53"}, created)

	// 204 carries no body, and the client must not try to decode one.
	asrt.NoError(h.client.Delete(ctx, "/hosts/b.example"))

	asrt.NoError(h.client.Ping(ctx))
}

// The socket's permissions are the entire authorization model, so this is the
// load-bearing assertion of the package.
func TestSocketIsNotGroupOrWorldAccessible(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, testMux())

	fi, err := os.Lstat(h.path)
	require.NoError(t, err)

	asrt.Equal(os.FileMode(0o600), fi.Mode().Perm(),
		"the socket must be 0600: its permissions are the only thing authorizing admin access")
	asrt.NotZero(fi.Mode()&os.ModeSocket, "the published path must be a socket")
}

// Listening on the final path and chmod'ing afterwards would leave a window in
// which the socket exists with umask-derived permissions. The staging rename
// closes it, so no umask can produce a permissive published socket.
func TestSocketModeIsIndependentOfUmask(t *testing.T) {
	asrt := assert.New(t)

	// A deliberately permissive umask: without the staging rename the socket
	// would appear 0777 before being tightened.
	old := setUmask(0)
	t.Cleanup(func() { setUmask(old) })

	h := newHarness(t, testMux())

	fi, err := os.Lstat(h.path)
	require.NoError(t, err)
	asrt.Equal(os.FileMode(0o600), fi.Mode().Perm())

	// And no staging file is left behind.
	_, err = os.Lstat(h.path + "~")
	asrt.ErrorIs(err, os.ErrNotExist)
}

// The parent directory is created 0700 when absent, so even the brief existence
// of the staging socket is not reachable by another user.
func TestSocketDirectoryIsCreatedPrivate(t *testing.T) {
	asrt := assert.New(t)

	dir, err := os.MkdirTemp("", "adm")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	nested := filepath.Join(dir, "run")
	path := filepath.Join(nested, "s")

	srv, err := admin.NewServer(admin.ServerOptions{
		Path:    path,
		Handler: testMux(),
		Logger:  log.New(log.WithOutput(&syncBuffer{})),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	fi, err := os.Stat(nested)
	require.NoError(t, err)
	asrt.Equal(os.FileMode(0o700), fi.Mode().Perm())
}

func TestServerRejectsIncompleteOptions(t *testing.T) {
	asrt := assert.New(t)

	_, err := admin.NewServer(admin.ServerOptions{Handler: testMux(), Logger: log.Default()})
	asrt.Error(err, "a socket path is required")

	_, err = admin.NewServer(admin.ServerOptions{Path: filepath.Join(t.TempDir(), "s"), Logger: log.Default()})
	asrt.Error(err, "a handler is required")

	// A nil logger is rejected rather than treated as "do not audit": all
	// three services are required to audit administrative actions.
	_, err = admin.NewServer(admin.ServerOptions{Path: filepath.Join(t.TempDir(), "s"), Handler: testMux()})
	asrt.Error(err)
	asrt.Contains(err.Error(), "audited")
}

// A handler's hint must survive the round trip, because the hint is the half of
// the error the operator can actually act on.
func TestErrorAndHintSurviveTheRoundTrip(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, testMux())

	err := h.client.Get(ctx, "/missing", nil)
	asrt.Error(err)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)
	asrt.Equal(http.StatusNotFound, adminErr.Status)
	asrt.Contains(adminErr.Message, `no such host "b.example"`)
	asrt.Equal("run `protean host list` to see the configured hosts", adminErr.Hint)
	asrt.Equal("run `protean host list` to see the configured hosts", admin.HintFor(err))

	// Error() is the message alone, so a wrapped chain does not repeat advice.
	asrt.NotContains(adminErr.Error(), "host list")
}

// A plain error from a handler becomes a 500 with no hint. An internal failure
// has no advice to offer, and inventing some would be worse than silence.
func TestNonAdminErrorBecomesInternalWithoutHint(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, testMux())

	err := h.client.Get(ctx, "/boom", nil)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)
	asrt.Equal(http.StatusInternalServerError, adminErr.Status)
	asrt.Contains(adminErr.Message, "provider credentials file")
	asrt.Empty(adminErr.Hint)
	asrt.Empty(admin.HintFor(err))
}

func TestHintForWalksAWrappedChain(t *testing.T) {
	asrt := assert.New(t)

	base := admin.Errorf(http.StatusConflict, "host already exists").WithHint("remove it first")
	wrapped := fmt.Errorf("adding host: %w", fmt.Errorf("validating: %w", base))

	asrt.Equal("remove it first", admin.HintFor(wrapped))
	asrt.Empty(admin.HintFor(errors.New("plain")), "an error with no hint anywhere must yield none")
	asrt.Empty(admin.HintFor(nil))
}

// The peer identity comes from the kernel, which is what makes it worth putting
// in an audit record at all.
func TestPeerCredentialsIdentifyTheCallingProcess(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, testMux())

	var got struct {
		Known    bool   `json:"known"`
		UID      uint32 `json:"uid"`
		PID      int32  `json:"pid"`
		Rendered string `json:"rendered"`
	}
	require.NoError(t, h.client.Get(ctx, "/whoami", &got))

	if !peerCredentialsSupported {
		asrt.False(got.Known, "a platform without SO_PEERCRED must report the peer as unknown")
		asrt.Equal("unknown", got.Rendered)

		return
	}

	asrt.True(got.Known)
	asrt.Equal(uint32(os.Getuid()), got.UID, "the peer uid must be this test process's uid")
	asrt.Equal(int32(os.Getpid()), got.PID, "the peer pid must be this test process's pid")
	asrt.Contains(got.Rendered, fmt.Sprintf("uid=%d", os.Getuid()))
}

// Mutations are audited at info and reads at debug, so that a monitoring script
// polling `host list` cannot bury the one `host remove` an auditor needs.
func TestAuditRecordsWhoWhatAndWhen(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, testMux())

	require.NoError(t, h.client.Post(ctx, "/hosts", hostPayload{Name: "c.example", Provider: "spaceship"}, nil))
	require.NoError(t, h.client.Get(ctx, "/hosts", nil))

	records := h.audit.String()
	asrt.Contains(records, `"method":"POST"`)
	asrt.Contains(records, `"path":"/hosts"`)
	asrt.Contains(records, `"status":201`)
	asrt.Contains(records, `"duration"`)
	asrt.Contains(records, `"level":"INFO"`, "a mutation is audited at info")
	asrt.Contains(records, `"level":"DEBUG"`, "a read is audited at debug")

	if peerCredentialsSupported {
		asrt.Contains(records, fmt.Sprintf("uid=%d", os.Getuid()), "the audit record must name the caller")
	}
}

// A socket file left behind by a crash must not stop the service restarting.
func TestStaleSocketIsReplaced(t *testing.T) {
	asrt := assert.New(t)

	dir, err := os.MkdirTemp("", "adm")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "s")

	// A socket file with nothing listening on it - exactly what an unclean
	// shutdown leaves.
	orphan, err := net.Listen("unix", path)
	require.NoError(t, err)
	if ul, ok := orphan.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	require.NoError(t, orphan.Close())

	_, err = os.Lstat(path)
	require.NoError(t, err, "the stale socket file must still be present")

	srv, err := admin.NewServer(admin.ServerOptions{
		Path:    path,
		Handler: testMux(),
		Logger:  log.New(log.WithOutput(&syncBuffer{})),
	})
	asrt.NoError(err, "a stale socket must be cleared, not treated as a running server")

	if srv != nil {
		_ = srv.Close()
	}
}

// A socket a server is still listening on must not be yanked away from it.
// Badger's directory lock already enforces one database owner; this makes the
// failure a clear message instead of a lock error.
func TestLiveSocketIsRefused(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, testMux())

	_, err := admin.NewServer(admin.ServerOptions{
		Path:    h.path,
		Handler: testMux(),
		Logger:  log.New(log.WithOutput(&syncBuffer{})),
	})
	asrt.Error(err)
	asrt.Contains(err.Error(), "already listening")
	asrt.Contains(admin.HintFor(err), "stop the running server")
}

func TestNonSocketPathIsRefused(t *testing.T) {
	asrt := assert.New(t)

	dir, err := os.MkdirTemp("", "adm")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "s")
	require.NoError(t, os.WriteFile(path, []byte("not a socket"), 0o600))

	_, err = admin.NewServer(admin.ServerOptions{
		Path:    path,
		Handler: testMux(),
		Logger:  log.New(log.WithOutput(&syncBuffer{})),
	})
	asrt.Error(err)
	asrt.Contains(err.Error(), "not a socket")
	asrt.NotEmpty(admin.HintFor(err), "refusing to clobber a regular file needs to say what to do instead")

	// And the file is left intact rather than removed.
	content, readErr := os.ReadFile(path)
	asrt.NoError(readErr)
	asrt.Equal("not a socket", string(content))
}

// The most common failure of any admin subcommand is "the server is not
// running", and the raw syscall error does not say so.
func TestClientExplainsAnAbsentServer(t *testing.T) {
	asrt := assert.New(t)

	dir, err := os.MkdirTemp("", "adm")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	client, err := admin.NewClient(admin.ClientOptions{
		Path:    filepath.Join(dir, "absent"),
		Timeout: 2 * time.Second,
	})
	require.NoError(t, err, "building a client must not require a running server")

	err = client.Get(context.Background(), "/hosts", nil)
	asrt.Error(err)
	asrt.Contains(admin.HintFor(err), "is the server running?")

	asrt.Error(client.Ping(context.Background()))
}

// Unknown fields are rejected so a mistyped flag fails loudly instead of
// silently creating a half-configured host.
func TestUnknownRequestFieldsAreRejected(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, testMux())

	err := h.client.Post(ctx, "/hosts", map[string]string{
		"name":    "d.example",
		"privder": "cloudflare", // a typo, not a field
	}, nil)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)
	asrt.Equal(http.StatusBadRequest, adminErr.Status)
	asrt.Contains(adminErr.Message, "malformed request body")
}

func TestShutdownRemovesTheSocket(t *testing.T) {
	asrt := assert.New(t)

	dir, err := os.MkdirTemp("", "adm")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "s")
	srv, err := admin.NewServer(admin.ServerOptions{
		Path:    path,
		Handler: testMux(),
		Logger:  log.New(log.WithOutput(&syncBuffer{})),
	})
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve()
	}()

	client, err := admin.NewClient(admin.ClientOptions{Path: path, Timeout: 5 * time.Second})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return client.Ping(context.Background()) == nil
	}, 5*time.Second, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	asrt.NoError(srv.Shutdown(ctx))
	<-done

	// A socket file left behind looks exactly like a running server to the
	// next start, so shutdown has to unlink it.
	_, err = os.Lstat(path)
	asrt.ErrorIs(err, os.ErrNotExist, "shutdown must remove the socket")

	// Shutdown and Close are both "last one out", so cleanup is idempotent.
	asrt.NoError(srv.Close())
}

// Concurrent admin requests must be served correctly - `server start` keeps the
// socket open for the life of the process and nothing serialises callers.
func TestConcurrentRequests(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, testMux())

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			var created hostPayload
			name := fmt.Sprintf("h%d.example", i)
			if err := h.client.Post(ctx, "/hosts", hostPayload{Name: name, Provider: "cloudflare"}, &created); err != nil {
				t.Errorf("POST /hosts: %v", err)

				return
			}

			if created.Name != name {
				t.Errorf("got host %q, want %q", created.Name, name)
			}
		}(i)
	}
	wg.Wait()
}

// A path cannot smuggle a newline into an audit record, which would let one
// request forge a second log line.
func TestAuditPathCannotForgeALogLine(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, testMux())

	conn, err := net.Dial("unix", h.path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Sent as a raw request, because net/http's client would reject the path.
	_, err = conn.Write([]byte("GET /hosts%0a%0dforged HTTP/1.1\r\nHost: admin\r\n\r\n"))
	require.NoError(t, err)

	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Read(buf)

	records := strings.TrimSpace(h.audit.String())

	// Only the request records; the buffer also holds the server's startup
	// line. Counting them guards against this test passing because nothing was
	// logged at all - the request has to have reached the audit middleware for
	// the assertions below to mean anything.
	var requests []string
	for _, line := range strings.Split(records, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, `"msg":"admin request"`) {
			requests = append(requests, line)
		}
	}

	require.Len(t, requests, 1, "one request must produce exactly one audit record, got: %s", records)
	asrt.True(strings.HasPrefix(requests[0], "{"), "an audit record must be one complete JSON object")
	asrt.True(strings.HasSuffix(requests[0], "}"), "an audit record must be one complete JSON object")

	// The path is still recorded - it is evidence - but with its line breaks
	// removed, so it cannot terminate the record early and append a line of
	// the caller's choosing.
	asrt.Contains(requests[0], `"path":"/hostsforged"`)
	asrt.NotContains(records, "forged\n")
}

// A socket path the kernel cannot bind must be rejected with an error saying
// so. bind(2) answers EINVAL, which surfaces as "invalid argument" and says
// nothing about path length.
func TestOverlongSocketPathIsRejected(t *testing.T) {
	asrt := assert.New(t)

	dir, err := os.MkdirTemp("", "adm")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// Build a path past the limit by nesting; the components stay short so the
	// failure is unambiguously about total length.
	long := dir
	for len(long) <= admin.MaxSocketPathLen {
		long = filepath.Join(long, "nested")
	}
	path := filepath.Join(long, "s")

	_, err = admin.NewServer(admin.ServerOptions{
		Path:    path,
		Handler: testMux(),
		Logger:  log.New(log.WithOutput(&syncBuffer{})),
	})
	asrt.Error(err)
	asrt.Contains(err.Error(), "kernel limit")
	asrt.NotEmpty(admin.HintFor(err), "the operator needs to be told to pick a shorter path")
}

// A path at the limit must still work, so the check is not off by one.
func TestSocketPathAtTheLimitWorks(t *testing.T) {
	asrt := assert.New(t)

	dir, err := os.MkdirTemp("", "adm")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	// Pad the basename so the absolute path is exactly at the limit.
	padding := admin.MaxSocketPathLen - len(dir) - 1
	require.Positive(t, padding, "the temp directory is already too long for this test")

	path := filepath.Join(dir, strings.Repeat("s", padding))
	require.Len(t, path, admin.MaxSocketPathLen)

	srv, err := admin.NewServer(admin.ServerOptions{
		Path:    path,
		Handler: testMux(),
		Logger:  log.New(log.WithOutput(&syncBuffer{})),
	})
	asrt.NoError(err, "a path exactly at the limit must bind, staging suffix included")

	if srv != nil {
		_ = srv.Close()
	}
}

// A path carrying a query string must reach the server as a query, not as part
// of the path. url.URL escapes "?" inside Path, so assigning the whole string
// to Path turns "/hosts?all=true" into "/hosts%3Fall=true" and matches no
// route - which is invisible until a command happens to pass a parameter.
func TestQueryStringsReachTheServer(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	var seen struct {
		mu    sync.Mutex
		path  string
		query string
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /things", func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.path, seen.query = r.URL.Path, r.URL.RawQuery
		seen.mu.Unlock()

		admin.WriteJSON(w, http.StatusOK, map[string]string{
			"filter": r.URL.Query().Get("filter"),
			"limit":  r.URL.Query().Get("limit"),
		})
	})

	h := newHarness(t, mux)

	var got map[string]string
	require.NoError(t, h.client.Get(ctx, "/things?filter=dead&limit=10", &got))

	seen.mu.Lock()
	path, query := seen.path, seen.query
	seen.mu.Unlock()

	asrt.Equal("/things", path, "the query must not be escaped into the path")
	asrt.Equal("filter=dead&limit=10", query)
	asrt.Equal("dead", got["filter"])
	asrt.Equal("10", got["limit"])

	// And a path with no query still works.
	require.NoError(t, h.client.Get(ctx, "/things", &got))
	asrt.Empty(got["filter"])
}

// A path segment containing a character that needs escaping must still reach
// the right route - hostnames are path segments in several of protean's admin
// routes.
func TestPathSegmentsAreEscaped(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	var seen struct {
		mu   sync.Mutex
		name string
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /hosts/{name}", func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.name = r.PathValue("name")
		seen.mu.Unlock()

		admin.WriteJSON(w, http.StatusOK, map[string]string{"name": r.PathValue("name")})
	})

	h := newHarness(t, mux)

	var got map[string]string
	require.NoError(t, h.client.Get(ctx, "/hosts/dyn.example.org", &got))

	seen.mu.Lock()
	name := seen.name
	seen.mu.Unlock()

	asrt.Equal("dyn.example.org", name)
	asrt.Equal("dyn.example.org", got["name"])
}
