package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/adnoctem/netory/pkg/log"
)

// Server serves an administrative HTTP handler over a Unix domain socket.
type Server struct {
	path    string
	logger  *log.Logger
	http    *http.Server
	ln      net.Listener
	cleanup sync.Once
}

// ServerOptions configures a Server.
type ServerOptions struct {
	// Path is the socket path. Its parent directory is created 0700 if absent.
	Path string

	// Handler serves admin requests. It is wrapped in the audit middleware.
	Handler http.Handler

	// Logger receives the audit records. Administrative actions must be
	// audited in all three services, so a nil Logger is an error rather than a
	// silent opt-out.
	Logger *log.Logger

	// ReadTimeout and WriteTimeout bound a single request. Zero uses
	// DefaultTimeout.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// DefaultTimeout bounds an admin request. Generous, because a provider test or
// a bundle publish legitimately takes seconds, but not unlimited - a wedged
// handler should not hold a connection open for the life of the process.
const DefaultTimeout = 2 * time.Minute

// stagingSuffix is appended to build the staging socket path.
//
// One byte, because it is charged against the kernel's socket path limit: the
// staging name has to fit too, so a longer suffix would make a socket path
// that the operator can use directly fail only because of how this package
// creates it.
const stagingSuffix = "~"

// MaxSocketPathLen is the longest socket path that can be bound.
//
// The kernel's sockaddr_un.sun_path is 108 bytes on Linux including its NUL
// terminator, so 107 characters are usable - and one of those is reserved for
// stagingSuffix. Exceeding it produces EINVAL from bind(2), which surfaces as
// "invalid argument" and says nothing at all about path length; validating
// here is what turns that into an error an operator can act on.
const MaxSocketPathLen = 107 - len(stagingSuffix)

// NewServer prepares a Server and creates its socket.
//
// The socket is created at a staging path, chmod'ed to 0600 and only then
// renamed into place. Listening directly on the final path and chmod'ing
// afterwards would leave a window in which the socket exists with permissions
// derived from the process umask - which is to say, possibly world-writable -
// and since those permissions are the entire authorization model, that window
// is the whole security boundary being briefly absent. Rename is atomic, so
// the socket never appears at its published path with the wrong mode.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Path == "" {
		return nil, errors.New("admin: socket path is required")
	}

	if opts.Handler == nil {
		return nil, errors.New("admin: handler is required")
	}

	if opts.Logger == nil {
		return nil, errors.New("admin: logger is required, administrative actions must be audited")
	}

	path, err := filepath.Abs(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("admin: resolve socket path %q: %w", opts.Path, err)
	}

	if err := checkSocketPathLen(path); err != nil {
		return nil, err
	}

	if err := prepareSocketDir(path); err != nil {
		return nil, err
	}

	if err := clearStaleSocket(path); err != nil {
		return nil, err
	}

	ln, err := listenSecurely(path)
	if err != nil {
		return nil, err
	}

	logger := opts.Logger.With(slog.String("component", "admin"))
	if !peerSupported() {
		logger.Warn("peer credentials unavailable", "reason", peerUnsupportedReason())
	}

	readTimeout, writeTimeout := opts.ReadTimeout, opts.WriteTimeout
	if readTimeout == 0 {
		readTimeout = DefaultTimeout
	}
	if writeTimeout == 0 {
		writeTimeout = DefaultTimeout
	}

	s := &Server{path: path, logger: logger, ln: ln}
	s.http = &http.Server{
		Handler:      audit(logger, opts.Handler),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,

		// ConnContext is the only hook with access to the net.Conn, so it is
		// where the kernel's view of the peer is captured. Reading it per
		// request is not possible - by the time a handler runs, the connection
		// is behind the http.ResponseWriter.
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if p, ok := peerOf(conn); ok {
				return withPeer(ctx, p)
			}

			return ctx
		},
	}

	return s, nil
}

// Path returns the absolute socket path.
func (s *Server) Path() string { return s.path }

// Serve accepts connections until the Server is shut down. It returns nil on a
// clean shutdown.
func (s *Server) Serve() error {
	defer s.removeSocket()

	s.logger.Info("admin socket listening", "path", s.path, "mode", fmt.Sprintf("%#o", DefaultSocketMode))

	if err := s.http.Serve(s.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("admin: serve %q: %w", s.path, err)
	}

	return nil
}

// Shutdown stops accepting connections and waits for in-flight requests, then
// removes the socket.
func (s *Server) Shutdown(ctx context.Context) error {
	defer s.removeSocket()

	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("admin: shutdown %q: %w", s.path, err)
	}

	return nil
}

// Close stops the Server immediately, dropping in-flight requests.
func (s *Server) Close() error {
	defer s.removeSocket()

	if err := s.http.Close(); err != nil {
		return fmt.Errorf("admin: close %q: %w", s.path, err)
	}

	return nil
}

// removeSocket unlinks the socket file. Go's unix listener already does this on
// Close, but Shutdown, Close and a failed Serve can each be the last one out,
// so this is idempotent and all three call it - a socket file left behind looks
// exactly like a running server to the next start.
func (s *Server) removeSocket() {
	s.cleanup.Do(func() {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.logger.Warn("could not remove admin socket", "path", s.path, "error", err)
		}
	})
}

// checkSocketPathLen rejects a socket path the kernel cannot bind.
//
// The path is resolved to an absolute one first, so a short relative path in a
// deeply nested working directory is measured as what will actually be bound.
func checkSocketPathLen(path string) error {
	if len(path) <= MaxSocketPathLen {
		return nil
	}

	return Errorf(0,
		"admin: socket path is %d bytes, but the kernel limit is %d: %q",
		len(path), MaxSocketPathLen, path,
	).WithHint("choose a shorter path, such as /run/%s/admin.sock", filepath.Base(filepath.Dir(path)))
}

// prepareSocketDir creates the socket's parent directory 0700 when it does not
// exist.
//
// An existing directory is left exactly as it is. Its permissions are the
// operator's decision - /run/protean is theirs to set up, and silently
// chmod'ing a directory this process does not own would be a worse surprise
// than the socket's own 0600 already being sufficient.
func prepareSocketDir(path string) error {
	dir := filepath.Dir(path)

	switch _, err := os.Stat(dir); {
	case err == nil:
		return nil
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("admin: stat socket directory %q: %w", dir, err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("admin: create socket directory %q: %w", dir, err)
	}

	return nil
}

// clearStaleSocket removes a leftover socket file, but refuses to remove one
// that something is still listening on.
//
// The distinction matters: a socket file surviving a crash must not stop the
// service from restarting, while a socket belonging to a running server must
// not be yanked out from under it. Dialling is what tells them apart - a
// successful connect means a live listener, a refused connect means a corpse.
func clearStaleSocket(path string) error {
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("admin: stat socket %q: %w", path, err)
	}

	if fi.Mode()&os.ModeSocket == 0 {
		return Errorf(0, "admin: %q exists and is not a socket", path).
			WithHint("choose a different socket path, or remove that file if it is not needed")
	}

	conn, dialErr := net.DialTimeout("unix", path, time.Second)
	if socketInUse(dialErr) {
		_ = conn.Close()

		return Errorf(0, "admin: another server is already listening on %q", path).
			WithHint("stop the running server first; only one process may own the database")
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("admin: remove stale socket %q: %w", path, err)
	}

	return nil
}

// listenSecurely binds the socket at a staging path, restricts it, and renames
// it into place, so it is never reachable with the wrong permissions.
func listenSecurely(path string) (net.Listener, error) {
	// The staging name sits in the same directory, so the rename is within one
	// filesystem and therefore atomic. A unix listener stays bound to its
	// inode across a rename, and a client connecting to the new name reaches
	// it - the path is only used to resolve the inode.
	staging := path + stagingSuffix
	if err := os.Remove(staging); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("admin: remove stale staging socket %q: %w", staging, err)
	}

	ln, err := net.Listen("unix", staging)
	if err != nil {
		return nil, fmt.Errorf("admin: listen on %q: %w", staging, err)
	}

	// Go's unix listener unlinks its path on Close. The rename below moves the
	// file out from under it, so that automatic cleanup would target a name
	// that no longer exists; removeSocket handles the real path instead.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}

	if err := os.Chmod(staging, DefaultSocketMode); err != nil {
		_ = ln.Close()
		_ = os.Remove(staging)

		return nil, fmt.Errorf("admin: restrict socket %q: %w", staging, err)
	}

	if err := os.Rename(staging, path); err != nil {
		_ = ln.Close()
		_ = os.Remove(staging)

		return nil, fmt.Errorf("admin: publish socket as %q: %w", path, err)
	}

	return ln, nil
}

// statusRecorder captures the status code for the audit record, since
// http.ResponseWriter does not expose what was written.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}

	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}

	return r.ResponseWriter.Write(b)
}

// audit wraps a handler so every administrative request is recorded with who,
// what and when.
//
// Reads are logged at debug and mutations at info, because `host list` run in a
// loop by a monitoring script would otherwise bury the one `host remove` that
// an auditor is looking for.
func audit(logger *log.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		rec := &statusRecorder{ResponseWriter: w}

		next.ServeHTTP(rec, r)

		if rec.status == 0 {
			rec.status = http.StatusOK
		}

		peer, _ := PeerFrom(r.Context())
		level := slog.LevelInfo
		if isRead(r.Method) {
			level = slog.LevelDebug
		}

		logger.Log(r.Context(), level, "admin request",
			slog.String("peer", peer.String()),
			slog.String("method", r.Method),
			slog.String("path", trimPath(r.URL.Path)),
			slog.Int("status", rec.status),
			slog.Duration("duration", time.Since(started)),
		)
	})
}

// isRead reports whether a method only reads state.
func isRead(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}
