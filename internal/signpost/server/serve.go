package server

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/adnoctem/netory/internal/signpost/app"
	"github.com/adnoctem/netory/internal/signpost/bundle"
	"github.com/adnoctem/netory/pkg/forwarded"
)

// Headers signpost sets on every served script.
const (
	// HeaderContentTypeOptions stops a browser from sniffing a script into
	// something it can execute in a page.
	HeaderContentTypeOptions = "X-Content-Type-Options"

	// HeaderRelease tells a client which release it just received, which is
	// the difference between "curl | sh did something odd" and a bug report
	// naming a version.
	HeaderRelease = "X-Signpost-Release"
)

// checksumContentType is what a `.sha256` route is served as.
//
// text/plain, and not the script's own type: the checksum is a line of hex
// about a script, not the script. Serving it as text/x-shellscript would be a
// small lie that a client piping by content type could act on.
const checksumContentType = "text/plain; charset=utf-8"

// publicHandler builds the network-facing mux.
//
// Three routes exist: the health endpoint, and everything else. There is no
// index and no listing - an unknown path returns 404 without
// revealing what is available, because a list of install scripts is a list of
// what this organisation deploys.
func (s *Server) publicHandler() http.Handler {
	mux := http.NewServeMux()

	// A liveness endpoint that touches neither the database nor the content
	// store, so it answers while the service is degraded and reports the
	// process itself.
	mux.HandleFunc("GET "+bundle.HealthPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", checksumContentType)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("HEAD "+bundle.HealthPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	})

	// One handler for every other path, dispatching on the method itself
	// rather than registering "GET /" and "HEAD /".
	//
	// net/http refuses that pair: "HEAD /" matches fewer methods than "GET
	// /healthz" while having a more general path, which the mux cannot order
	// and so rejects outright. Switching here is the honest way round, and it
	// keeps the method policy in one place.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			// HEAD is served for the same paths as GET, because `curl -I` on
			// an install URL is how a cautious operator checks what they are
			// about to run. net/http discards the body for a HEAD itself, so
			// handleScript does not need to know.
			s.handleScript(w, r)
		default:
			// A POST to an install path is a 405 rather than a 404. The path
			// may well exist; the method is what is wrong, and saying so
			// reveals nothing a GET would not.
			w.Header().Set("Allow", "GET, HEAD")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	return mux
}

// handleScript serves one script, its checksum, or a 404.
func (s *Server) handleScript(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	started := time.Now()

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		s.log.Error("could not read settings", "error", err)
		s.fail(w, http.StatusInternalServerError)

		return
	}

	// HTTPS before anything else, including before the path is resolved.
	//
	// Plain HTTP is not served scripts, and it has to be enforced rather
	// than preferred: the client is about to
	// pipe the response into a shell, and a downgrade that silently succeeds
	// is the one failure this service exists to prevent. Checked first so a
	// plaintext request cannot even learn which paths exist.
	if !s.permitTransport(w, r, settings) {
		return
	}

	resolution, ok := s.state.Table().Resolve(r.URL.Path)
	if !ok {
		s.access(r, settings, r.URL.Path, http.StatusNotFound, 0, "", started)
		s.fail(w, http.StatusNotFound)

		return
	}

	content, err := s.state.ServeContent(ctx, resolution)
	if err != nil {
		// A route in the table whose bytes are missing or no longer hash to
		// their name. Both mean the metadata and the content have diverged,
		// which is a fault to report loudly rather than a 404 to serve
		// quietly - and under no circumstances bytes to serve anyway.
		level := "could not read the content of a published route"
		if errors.Is(err, app.ErrDigestMismatch) {
			level = "refusing to serve content that does not match its published digest"
		}

		s.log.Error(level,
			"path", r.URL.Path,
			"release", resolution.Release,
			"digest", resolution.Route.SHA256,
			"error", err)

		s.access(r, settings, r.URL.Path, http.StatusInternalServerError, 0, resolution.Release, started)
		s.fail(w, http.StatusInternalServerError)

		return
	}

	if resolution.Checksum {
		// The content was fetched even though the checksum comes from the
		// release record, and that is the point: ServeContent verifies the
		// stored bytes against their digest, so a checksum is never published
		// for a file that has since been altered on disk. A cautious user
		// fetching the checksum before the script gets the same guarantee the
		// script itself would have given them.
		s.writeChecksum(w, r, resolution, settings, started)

		return
	}

	s.writeScript(w, r, resolution, settings, content, started)
}

// writeScript serves a route's content.
func (s *Server) writeScript(
	w http.ResponseWriter,
	r *http.Request,
	res app.Resolution,
	settings app.Settings,
	content []byte,
	started time.Time,
) {
	header := w.Header()
	header.Set("Content-Type", res.Route.ContentType)
	header.Set(HeaderContentTypeOptions, "nosniff")
	header.Set(HeaderRelease, res.Release)
	header.Set("ETag", etag(res.Route.SHA256))
	header.Set("Cache-Control", cacheControl(res, settings))

	// Content-Length rather than chunked, and it matters here more than it
	// usually does: a client piping into a shell can only detect a truncated
	// download if it was told how much to expect. The truncation check is
	// the belt; this is the braces.
	header.Set("Content-Length", strconv.Itoa(len(content)))

	status := http.StatusOK
	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, res.Route.SHA256) {
		status = http.StatusNotModified
	}

	s.access(r, settings, r.URL.Path, status, len(content), res.Release, started)

	if status == http.StatusNotModified {
		// A 304 must carry no body, and net/http would complain about the
		// Content-Length if it stayed.
		header.Del("Content-Length")
		w.WriteHeader(status)

		return
	}

	w.WriteHeader(status)
	_, _ = w.Write(content)
}

// writeChecksum serves a route's `.sha256` sibling.
//
// Formatted as sha256sum's output - digest, two spaces, name - so an operator
// can pipe it straight into `sha256sum -c` without reformatting. The name is
// the route's basename, which is what the file will be called once they have
// downloaded it.
func (s *Server) writeChecksum(
	w http.ResponseWriter,
	r *http.Request,
	res app.Resolution,
	settings app.Settings,
	started time.Time,
) {
	name := res.Route.Path
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}

	body := fmt.Sprintf("%s  %s\n", res.Route.SHA256, name)

	header := w.Header()
	header.Set("Content-Type", checksumContentType)
	header.Set(HeaderContentTypeOptions, "nosniff")
	header.Set(HeaderRelease, res.Release)
	header.Set("Cache-Control", cacheControl(res, settings))
	header.Set("Content-Length", strconv.Itoa(len(body)))

	// Deliberately not the script's ETag. The checksum document is a
	// different resource from the script, and giving them the same validator
	// would let a cache serve one for the other. A suffixed digest is enough
	// to be distinct and still change exactly when the script does.
	header.Set("ETag", etag(res.Route.SHA256+bundle.ChecksumSuffix))

	s.access(r, settings, r.URL.Path, http.StatusOK, len(body), res.Release, started)

	_, _ = w.Write([]byte(body))
}

// permitTransport enforces the HTTPS-only requirement, answering false when
// the request must not be served.
func (s *Server) permitTransport(w http.ResponseWriter, r *http.Request, settings app.Settings) bool {
	state := s.forwarded.Encryption(r)
	if state == forwarded.Encrypted {
		return true
	}

	// Unknown means proxy mode with no trusted set declared, or a trusted
	// proxy that sends no X-Forwarded-Proto. Refused rather than served:
	// signpost cannot confirm the hop was encrypted, and "probably encrypted"
	// is not a guarantee to stake executable content on. The startup log says
	// so at warn, so an operator meets this as a documented configuration
	// error rather than a mystery.
	s.log.Warn("refusing to serve a script over a connection that cannot be confirmed as HTTPS",
		"path", r.URL.Path,
		"transport", state.String(),
		"hint", transportHint(state, s.forwarded.Enforced(), s.state.Config.ProxyMode()))

	// 421 Misdirected Request: the request reached a server that is not
	// willing to answer for this connection, which is exactly the situation.
	// A redirect to https:// would be the friendlier answer and the wrong one
	// - a client that followed it would have already sent the request in the
	// clear, and `curl | sh` without -L would pipe the redirect body into a
	// shell.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", checksumContentType)
	w.WriteHeader(http.StatusMisdirectedRequest)
	_, _ = w.Write([]byte("signpost serves scripts over HTTPS only\n"))

	s.access(r, settings, r.URL.Path, http.StatusMisdirectedRequest, 0, "", time.Now())

	return false
}

// transportHint names the likely misconfiguration behind a refusal.
func transportHint(state forwarded.State, enforced, proxyMode bool) string {
	switch {
	case state == forwarded.Plaintext:
		return "the request arrived over plain HTTP"
	case proxyMode && !enforced:
		return "no trusted proxies are configured, so X-Forwarded-Proto is ignored"
	case proxyMode:
		return "the proxy did not send X-Forwarded-Proto: https"
	default:
		return "the connection was not TLS"
	}
}

// fail writes a status with no body and no detail.
//
// Unknown paths return 404 without listing available routes, and the
// same reasoning applies to every other failure on the public listener: the
// client is anonymous, and nothing it is told helps it more than it helps
// someone mapping the service.
func (s *Server) fail(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
}

// etag renders a digest as a strong ETag.
//
// Strong rather than weak, and quoted: the digest identifies the bytes exactly,
// which is what a strong validator asserts. Derived from the content hash
// rather than from a timestamp, so a republished identical file keeps
// its validator and a changed one cannot keep it by accident.
func etag(digest string) string { return `"` + digest + `"` }

// etagMatches reports whether an If-None-Match header covers a digest.
//
// A list is parsed because that is what the header is, and `*` is honoured
// because a conditional request with `*` means "if you have any version of
// this" - which, for an immutable resource, we do.
func etagMatches(header, digest string) bool {
	want := etag(digest)

	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == want {
			return true
		}

		// A weak validator sent back for a strong one still identifies the
		// same bytes here, since the only validator signpost issues is the
		// content hash.
		if strings.TrimPrefix(candidate, "W/") == want {
			return true
		}
	}

	return false
}

// cacheControl renders the cache lifetime for a resolution.
//
// The cache-lifetime split, and the reason for it is mutability rather than
// taste: an alias route changes meaning at the next publish, so a long cache
// would keep serving a release a rollback was meant to retract. A versioned
// route cannot change by construction, so it is immutable and cacheable for as
// long as HTTP allows.
func cacheControl(res app.Resolution, settings app.Settings) string {
	if res.Versioned {
		seconds := int64(settings.CacheVersionMaxAge.Seconds())
		if seconds <= 0 {
			return "no-store"
		}

		return "public, max-age=" + strconv.FormatInt(seconds, 10) + ", immutable"
	}

	seconds := int64(settings.CacheAliasMaxAge.Seconds())
	if seconds <= 0 {
		return "no-store"
	}

	// must-revalidate rather than a bare max-age: once the lifetime is up, a
	// cache must ask rather than serve stale on a slow origin. A stale install
	// script is the thing a short lifetime was chosen to avoid.
	return "public, max-age=" + strconv.FormatInt(seconds, 10) + ", must-revalidate"
}
