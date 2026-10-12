//go:build e2e

package pivot

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/valkey"
)

// AdoptEnv names an already-running Valkey. When it is set the test uses that
// instead of starting a container, which turns local iteration into one
// `docker run` followed by as many fast runs as you like.
const AdoptEnv = "PIVOT_E2E_VALKEY"

// ValkeyImage is the image the container is started from.
//
// Pinned to a major-minor tag rather than a digest: this test exists partly to
// catch upstream rot, so following patch releases is the point. A digest would
// pin away the thing being watched for.
const ValkeyImage = "valkey/valkey:9-alpine"

// readyTimeout bounds the wait for a replica to serve.
const readyTimeout = 30 * time.Second

// Stack is everything the test drives: a Valkey, a backend, and the pivot
// replicas in front of them.
type Stack struct {
	// Valkey is the store address, host:port.
	Valkey string

	// Backend stands in for the production API.
	Backend *Backend

	// Binary is the pivot executable under test.
	Binary string

	// Secret is the service secret file every replica shares. They must:
	// keys derived from it decrypt the backend credentials in Valkey, so a
	// replica with a different one starts cleanly and then fails every
	// forward leg.
	Secret string

	// DB is the Valkey logical database this run uses.
	DB int

	t        *testing.T
	replicas []*Replica
}

// Replica is one running `pivot server start`.
type Replica struct {
	// Name is the replica identity, which appears in its log lines and in
	// outbox claims.
	Name string

	// ProxyURL is the customer-facing origin.
	ProxyURL string

	// Socket is the admin socket path.
	Socket string

	cmd  *exec.Cmd
	log  *logBuffer
	done chan struct{}
}

// Start brings up a Valkey, a backend and the pivot binary.
func Start(t *testing.T) *Stack {
	t.Helper()

	requireDocker(t)

	stack := &Stack{
		t:       t,
		Backend: startBackend(t),
		Binary:  buildBinary(t),
		Secret:  writeSecret(t),

		// A database of its own per run, so a developer's existing keys and
		// two concurrent runs cannot see each other.
		DB: 9,
	}

	stack.Valkey = startValkey(t)

	return stack
}

// requireDocker skips the test when no Docker daemon is reachable.
func requireDocker(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed; this test needs a Docker daemon")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	probe := exec.CommandContext(ctx, "docker", "info")
	if output, err := probe.CombinedOutput(); err != nil {
		t.Skipf("docker is installed but not usable (%v):\n%s", err, output)
	}
}

// startValkey returns a Valkey address, from the environment or a container.
func startValkey(t *testing.T) string {
	t.Helper()

	if adopted := strings.TrimSpace(os.Getenv(AdoptEnv)); adopted != "" {
		t.Logf("using the Valkey at %s (%s is set); this run manages no container",
			adopted, AdoptEnv)

		return adopted
	}

	ctx := context.Background()

	container, err := valkey.Run(ctx, ValkeyImage)
	require.NoError(t, err, "could not start a Valkey container")

	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(container); err != nil {
			t.Logf("could not terminate the Valkey container: %v", err)
		}
	})

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)

	return net.JoinHostPort(host, port.Port())
}

// buildBinary compiles the pivot binary under test.
//
// Built rather than assumed on PATH, so the test is always exercising this
// working tree. It is the whole reason this test catches flag and environment
// wiring: the unit tests drive an in-process handler and never see main.
func buildBinary(t *testing.T) string {
	t.Helper()

	root := repoRoot(t)
	binary := filepath.Join(t.TempDir(), "pivot")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/pivot")
	build.Dir = root

	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("could not build the pivot binary: %v\n%s", err, output)
	}

	return binary
}

// ExamplePath returns the path of a documented example rule document.
//
// The suite applies the same file the documentation tells an operator to copy,
// rather than a rule set written for the test. pivot ships no rule set, so if
// that file were wrong there would be nothing else to be right - and §10.6
// rests on the Shopware example having been checked against a backend
// speaking the Admin API's shapes.
func ExamplePath(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(repoRoot(t), "docs", "examples", "pivot", name)
	_, err := os.Stat(path)
	require.NoError(t, err, "the documented example is missing")

	return path
}

// repoRoot walks up from the test's directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}

		parent := filepath.Dir(dir)
		require.NotEqual(t, parent, dir, "could not find the module root above %s", dir)

		dir = parent
	}
}

// writeSecret generates the service secret and writes it to a file.
//
// Generated per run rather than fixed: nothing for gitleaks to find, no
// throwaway secret in the repository, and one run cannot decrypt another's
// leftovers.
func writeSecret(t *testing.T) string {
	t.Helper()

	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(buf)), 0o600))

	return path
}

// StartReplica starts a `pivot server start` and waits for it to serve.
//
// The socket goes in a short directory because a Unix socket path is limited
// to 108 bytes on Linux and t.TempDir names are derived from the test name.
func (s *Stack) StartReplica(name string) *Replica {
	s.t.Helper()

	socketDir, err := os.MkdirTemp("", "pv")
	require.NoError(s.t, err)
	s.t.Cleanup(func() { _ = os.RemoveAll(socketDir) })

	port := freePort(s.t)

	replica := &Replica{
		Name:     name,
		ProxyURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		Socket:   filepath.Join(socketDir, "admin.sock"),
		log:      &logBuffer{},
		done:     make(chan struct{}),
	}

	//nolint:gosec // the binary is the one this test just built
	replica.cmd = exec.Command(s.Binary, "server", "start")
	replica.cmd.Env = append(os.Environ(),
		"PIVOT_SECRET_FILE="+s.Secret,
		"PIVOT_SOCKET="+replica.Socket,
		fmt.Sprintf("PIVOT_LISTEN=127.0.0.1:%d", port),
		"PIVOT_VALKEY_ADDRESS="+s.Valkey,
		fmt.Sprintf("PIVOT_VALKEY_DB=%d", s.DB),
		"PIVOT_REPLICA="+name,

		// Loopback is declared trusted so the test can present
		// X-Forwarded-Proto and have it believed, which is what an ingress
		// would do. Without it pivot cannot tell the transport and tolerates
		// the request rather than refusing it - correct, but it would leave
		// the HTTPS enforcement untested.
		"PIVOT_TRUSTED_PROXIES=127.0.0.1",
		"PIVOT_LOG_FORMAT=json",
	)
	replica.cmd.Stdout = replica.log
	replica.cmd.Stderr = replica.log

	require.NoError(s.t, replica.cmd.Start())

	go func() {
		_ = replica.cmd.Wait()
		close(replica.done)
	}()

	s.replicas = append(s.replicas, replica)

	s.t.Cleanup(func() { replica.stop(s.t) })

	replica.waitReady(s.t)

	return replica
}

// waitReady blocks until the replica answers its health endpoint.
func (r *Replica) waitReady(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(readyTimeout)

	for time.Now().Before(deadline) {
		select {
		case <-r.done:
			t.Fatalf("replica %s exited before it was ready:\n%s", r.Name, r.log.String())
		default:
		}

		resp, err := http.Get(r.ProxyURL + "/healthz") //nolint:noctx // a readiness poll
		if err == nil {
			_ = resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				return
			}
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("replica %s did not become ready within %s:\n%s", r.Name, readyTimeout, r.log.String())
}

// stop sends SIGTERM and waits for the replica to exit.
//
// SIGTERM rather than Kill, because the graceful path is part of what is under
// test: in-flight requests finish and outbox claims are released rather than
// left to their lease.
func (r *Replica) stop(t *testing.T) {
	t.Helper()

	if r.cmd.Process == nil {
		return
	}

	_ = r.cmd.Process.Signal(os.Interrupt)

	select {
	case <-r.done:
	case <-time.After(20 * time.Second):
		t.Logf("replica %s did not stop gracefully; killing it", r.Name)
		_ = r.cmd.Process.Kill()
		<-r.done
	}
}

// Log returns everything the replica has written.
func (r *Replica) Log() string { return r.log.String() }

// LogMark returns how much the replica has written so far, for WaitForLog.
//
// Taken before whatever is supposed to produce the line, because the line may
// already be there by the time the wait starts.
func (r *Replica) LogMark() int { return r.log.Len() }

// WaitForLog blocks until the replica logs a line containing substr after mark.
//
// Used for the one thing that cannot be observed through an HTTP response: a
// replica reloading because another replica announced a change.
//
// The mark is the whole point, and the reason this takes one. Searching the
// accumulated log instead makes every wait after the first return
// immediately, on a line an earlier step produced - so "wait for the reload"
// quietly becomes "a reload happened at some point", and the assertion that
// follows races the thing it was waiting for. That showed up as a 403 where a
// 200 was expected, in one run out of four.
func (r *Replica) WaitForLog(t *testing.T, mark int, substr string, within time.Duration) {
	t.Helper()

	deadline := time.Now().Add(within)

	for time.Now().Before(deadline) {
		if written := r.log.String(); len(written) > mark &&
			strings.Contains(written[mark:], substr) {
			return
		}

		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("replica %s never logged %q within %s of offset %d:\n%s",
		r.Name, substr, within, mark, r.log.String())
}

// CLI runs a pivot subcommand against this replica's admin socket.
//
// Every configuration change in this test goes through here rather than
// through the Go API, because the CLI is the thing an operator types and the
// unit tests never touch it.
func (s *Stack) CLI(replica *Replica, args ...string) (string, error) {
	s.t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	//nolint:gosec // the binary is the one this test just built
	cmd := exec.CommandContext(ctx, s.Binary, args...)
	cmd.Env = append(os.Environ(),
		"PIVOT_SOCKET="+replica.Socket,
		"PIVOT_SECRET_FILE="+s.Secret,
	)

	output, err := cmd.CombinedOutput()

	return string(output), err
}

// MustCLI runs a subcommand and fails the test if it does not succeed.
func (s *Stack) MustCLI(replica *Replica, args ...string) string {
	s.t.Helper()

	output, err := s.CLI(replica, args...)
	require.NoError(s.t, err, "pivot %s failed:\n%s", strings.Join(args, " "), output)

	return output
}

// logBuffer collects a process's output, safely for concurrent writes.
type logBuffer struct {
	mu    sync.Mutex
	lines strings.Builder
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.lines.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.lines.String()
}

// Len is how much has been written, which WaitForLog uses as a starting
// offset so it waits for a new line rather than matching an old one.
func (b *logBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.lines.Len()
}

// freePort asks the kernel for an unused port.
func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	return port
}

// Backend stands in for the production API pivot fronts.
//
// It speaks the shapes the Shopware Admin API does - an oauth2
// client-credentials token endpoint, entity routes, and search endpoints that
// take their query in a POST body - which is what makes the documented example
// testable without deploying Shopware and a database. It also records what it
// was sent, so the test can assert on the forward leg rather than inferring it
// from a response.
type Backend struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []Request

	// tokens counts token requests, which is how the shared backend-token
	// cache is observed: without it, two replicas would each fetch their own.
	tokens atomic.Int64

	// handler overrides the default behaviour for a test that needs a
	// specific response.
	handler atomic.Pointer[http.HandlerFunc]
}

// Request is one forwarded request as the backend saw it.
type Request struct {
	Method string
	Path   string
	Query  string
	Auth   string
	APIKey string
	Body   string
}

// BackendCredentials are what the fake backend accepts.
const (
	BackendClientID     = "SWIAbackendclientid"
	BackendClientSecret = "backend-client-secret-value"
	BackendUsername     = "backend-basic-user"
	BackendPassword     = "backend-basic-password"
	BackendAPIKey       = "backend-api-key-value"
)

// startBackend brings up the fake production API.
func startBackend(t *testing.T) *Backend {
	t.Helper()

	backend := &Backend{}

	backend.server = httptest.NewServer(http.HandlerFunc(backend.serve))
	t.Cleanup(backend.server.Close)

	return backend
}

// URL returns the backend origin.
func (b *Backend) URL() string { return b.server.URL }

// serve answers a request and records it.
func (b *Backend) serve(w http.ResponseWriter, r *http.Request) {
	body := readAll(r)

	b.mu.Lock()
	b.requests = append(b.requests, Request{
		Method: r.Method,
		Path:   r.URL.Path,
		Query:  r.URL.RawQuery,
		Auth:   r.Header.Get("Authorization"),
		APIKey: r.Header.Get("X-Api-Key"),
		Body:   body,
	})
	b.mu.Unlock()

	// The token endpoint, as Shopware's Admin API presents it.
	if r.URL.Path == "/api/oauth/token" {
		b.serveToken(w, r)

		return
	}

	if handler := b.handler.Load(); handler != nil {
		(*handler)(w, r)

		return
	}

	if !b.authorized(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"code":"invalid_token"}]}`))

		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"total": 1,
		"data":  []map[string]string{{"id": "0123456789abcdef0123456789abcdef", "path": r.URL.Path}},
	})
}

// serveToken answers a client-credentials request.
func (b *Backend) serveToken(w http.ResponseWriter, r *http.Request) {
	b.tokens.Add(1)

	_ = r.ParseForm()

	id := r.PostForm.Get("client_id")
	secret := r.PostForm.Get("client_secret")

	if headerID, headerSecret, ok := r.BasicAuth(); ok {
		id, secret = headerID, headerSecret
	}

	w.Header().Set("Content-Type", "application/json")

	if id != BackendClientID || secret != BackendClientSecret {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"code":"invalid_client"}]}`))

		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"token_type":   "Bearer",
		"expires_in":   600,
		"access_token": fmt.Sprintf("backend-token-%d", b.tokens.Load()),
	})
}

// authorized reports whether a request carried credentials the backend
// accepts, in any of the three modes.
func (b *Backend) authorized(r *http.Request) bool {
	if key := r.Header.Get("X-Api-Key"); key != "" {
		return key == BackendAPIKey
	}

	header := r.Header.Get("Authorization")

	if strings.HasPrefix(header, "Bearer backend-token-") {
		return true
	}

	if user, password, ok := r.BasicAuth(); ok {
		return user == BackendUsername && password == BackendPassword
	}

	return false
}

// SetHandler replaces the backend's behaviour for the non-token routes.
func (b *Backend) SetHandler(handler http.HandlerFunc) { b.handler.Store(&handler) }

// Requests returns everything the backend was sent.
func (b *Backend) Requests() []Request {
	b.mu.Lock()
	defer b.mu.Unlock()

	return append([]Request(nil), b.requests...)
}

// Last returns the most recent non-token request.
func (b *Backend) Last(t *testing.T) Request {
	t.Helper()

	requests := b.Requests()

	for i := len(requests) - 1; i >= 0; i-- {
		if requests[i].Path != "/api/oauth/token" {
			return requests[i]
		}
	}

	t.Fatal("the backend received no proxied request")

	return Request{}
}

// Count returns how many non-token requests reached the backend.
func (b *Backend) Count() int {
	count := 0

	for _, request := range b.Requests() {
		if request.Path != "/api/oauth/token" {
			count++
		}
	}

	return count
}

// TokenRequests returns how many times the backend's token endpoint was asked
// for a token.
func (b *Backend) TokenRequests() int64 { return b.tokens.Load() }

// readAll reads a request body without failing the handler.
func readAll(r *http.Request) string {
	if r.Body == nil {
		return ""
	}

	var out strings.Builder

	scanner := bufio.NewScanner(r.Body)
	for scanner.Scan() {
		out.Write(scanner.Bytes())
	}

	return out.String()
}
