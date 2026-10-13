// Package bundle parses, validates and unpacks signpost bundles.
//
// A bundle is one archive carrying scripts plus exactly one manifest. Every
// byte of it arrives from outside, and the archive has to be unpacked before
// anything in it can be checked - which makes this package the one component
// processing attacker-shaped input before any other validation has run. The
// hardening in extract.go is where that is taken seriously.
//
// # The manifest is validated in Go, and the schema is published
//
// The Go validation here is authoritative; schema.json is generated from these
// types and published so an editor or a CI step can check a manifest before it
// reaches signpost. A test asserts the two agree, because a schema that says
// yes where the server says no is worse than no schema at all.
package bundle

import (
	"errors"
	"fmt"
	"mime"
	"path"
	"regexp"
	"strings"
)

// ManifestVersion is the only manifest schema version this build understands.
//
// Checked rather than ignored: a manifest written for a future version is
// rejected with a message saying so, instead of being read with fields
// silently missing.
const ManifestVersion = 1

// ManifestNames are the accepted manifest filenames at the archive root.
//
// A fixed list rather than a search: the manifest must be unambiguous, and
// "whichever YAML file we found first" is not a contract anyone can rely on.
var ManifestNames = []string{
	"signpost.yaml",
	"signpost.yml",
	"signpost.json",
}

// Limits on the manifest itself, independent of the archive limits.
const (
	// MaxRoutes bounds how many paths one bundle may serve. Generous for the
	// install-script case this exists for, and bounded so a manifest cannot
	// make the route table unbounded.
	MaxRoutes = 256

	// MaxPathLen bounds a route path.
	MaxPathLen = 512

	// MaxReleaseLen bounds a release identifier.
	MaxReleaseLen = 64
)

// Manifest is a bundle's manifest.
type Manifest struct {
	// Version is the manifest schema version. Must equal ManifestVersion.
	Version int `json:"version" yaml:"version"`

	// Release identifies this bundle, and must be unique per signpost
	// instance - that uniqueness is what makes a release immutable rather
	// than merely conventionally immutable.
	Release string `json:"release" yaml:"release"`

	// Description is an optional note shown by `bundle list`.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Routes are the paths this bundle serves.
	Routes []Route `json:"routes" yaml:"routes"`
}

// Route maps a served path to a file inside the bundle.
type Route struct {
	// Path is the URL path, which must begin with "/".
	Path string `json:"path" yaml:"path"`

	// File is the path inside the archive, relative to its root.
	File string `json:"file" yaml:"file"`

	// ContentType is the Content-Type to serve. Optional; inferred from the
	// file extension when absent.
	ContentType string `json:"content_type,omitempty" yaml:"content_type,omitempty"`

	// SkipTruncationCheck opts one route out of the structural truncation check.
	//
	// It exists because the check is a heuristic over shell syntax and will
	// occasionally be wrong about a legitimate script. Opting out is a
	// deliberate, recorded act rather than a silent default: `bundle list`
	// reports it, and the publish event carries it, so a bundle that skipped
	// the check is visible afterwards.
	SkipTruncationCheck bool `json:"skip_truncation_check,omitempty" yaml:"skip_truncation_check,omitempty"`
}

// Reserved route paths and suffixes.
//
// A route may not collide with the server's own paths, or with the derived
// paths it serves. Checked at validation so a bundle cannot shadow them -
// shadowing /healthz would make the service look unhealthy, and shadowing a.
// sha256 path would make a checksum lie about which bytes it covers.
const (
	// ChecksumSuffix is appended to every route to serve its SHA-256.
	ChecksumSuffix = ".sha256"

	// HealthPath is the server's liveness endpoint.
	HealthPath = "/healthz"
)

// versionedPrefix matches a first path segment reserved for versioned access.
//
// Versioned routes are served at /v<release>/<path>, so a bundle route
// whose first segment looks like that would be unreachable - the versioned
// resolver would claim it first. Rejecting it at validation turns a confusing
// silent shadowing into an error naming the problem.
var versionedPrefix = regexp.MustCompile(`^v[0-9]`)

// IsVersionedSegment reports whether a first path segment is one signpost
// reserves for versioned access.
//
// Exported so the server's path resolver and this validator share one rule.
// Two copies of "looks like /v1.4.0" would be one copy too many: if they ever
// disagreed, a bundle could publish a route the resolver claims first, and the
// route would silently never be served.
func IsVersionedSegment(segment string) bool {
	return versionedPrefix.MatchString(segment)
}

// pathSegment is the character set allowed in a route path segment.
//
// Deliberately narrow. A route path is both a URL and, for the checksum
// sibling, a derived string; keeping it to unreserved URL characters means
// there is never a question of how it is encoded, and no percent-encoding to
// normalise before matching.
var pathSegment = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Sentinel errors.
var (
	// ErrNoManifest is returned when an archive carries no manifest.
	ErrNoManifest = errors.New("bundle: no manifest found at the archive root")

	// ErrMultipleManifests is returned when an archive carries more than one.
	ErrMultipleManifests = errors.New("bundle: more than one manifest at the archive root")

	// ErrUnsupportedVersion is returned for a manifest version this build does
	// not understand.
	ErrUnsupportedVersion = errors.New("bundle: unsupported manifest version")
)

// Validate reports whether the manifest is one signpost can publish.
//
// Every failure names the offending route by index and path, because a
// rejected bundle is rejected whole and the operator needs to know which
// entry to fix rather than being told the bundle is invalid.
func (m *Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf(
			"%w: %d, this build understands %d",
			ErrUnsupportedVersion, m.Version, ManifestVersion)
	}

	if err := ValidateRelease(m.Release); err != nil {
		return err
	}

	if len(m.Routes) == 0 {
		return errors.New("bundle: the manifest declares no routes")
	}

	if len(m.Routes) > MaxRoutes {
		return fmt.Errorf("bundle: %d routes exceeds the limit of %d", len(m.Routes), MaxRoutes)
	}

	seenPaths := make(map[string]int, len(m.Routes))

	for i := range m.Routes {
		route := &m.Routes[i]

		if err := route.validate(); err != nil {
			return fmt.Errorf("bundle: route %d (%s): %w", i, route.Path, err)
		}

		// Duplicate paths are an error rather than last-one-wins: a manifest
		// declaring one path twice is ambiguous about which file it serves,
		// and guessing would be worse than refusing.
		if previous, duplicate := seenPaths[route.Path]; duplicate {
			return fmt.Errorf(
				"bundle: route %d duplicates the path %q already declared by route %d",
				i, route.Path, previous)
		}

		seenPaths[route.Path] = i
	}

	return nil
}

// validate checks one route.
func (r *Route) validate() error {
	if r.Path == "" {
		return errors.New("path is empty")
	}

	if len(r.Path) > MaxPathLen {
		return fmt.Errorf("path is %d bytes, the limit is %d", len(r.Path), MaxPathLen)
	}

	if !strings.HasPrefix(r.Path, "/") {
		return fmt.Errorf("path %q must begin with %q", r.Path, "/")
	}

	// The path must already be canonical. Accepting "/a/../b" and cleaning it
	// would mean the manifest says one thing and the server serves another,
	// and the checksum path is derived from this string.
	if cleaned := path.Clean(r.Path); cleaned != r.Path {
		return fmt.Errorf("path %q is not canonical, use %q", r.Path, cleaned)
	}

	if strings.HasSuffix(r.Path, ChecksumSuffix) {
		return fmt.Errorf(
			"path %q ends in %q, which is reserved: signpost serves every route's checksum there",
			r.Path, ChecksumSuffix)
	}

	if r.Path == HealthPath {
		return fmt.Errorf("path %q is reserved for the server's liveness endpoint", r.Path)
	}

	segments := strings.Split(strings.TrimPrefix(r.Path, "/"), "/")
	for i, segment := range segments {
		if segment == "" {
			return fmt.Errorf("path %q contains an empty segment", r.Path)
		}

		if !pathSegment.MatchString(segment) {
			return fmt.Errorf(
				"path segment %q may only contain letters, digits, '.', '_' and '-'", segment)
		}

		if i == 0 && IsVersionedSegment(segment) {
			return fmt.Errorf(
				"path %q starts with %q, which is reserved: signpost serves versioned routes at /v<release>/<path>",
				r.Path, segment)
		}
	}

	if err := validateArchivePath(r.File); err != nil {
		return err
	}

	if r.ContentType != "" {
		if _, _, err := mime.ParseMediaType(r.ContentType); err != nil {
			return fmt.Errorf("content_type %q is not a media type: %w", r.ContentType, err)
		}
	}

	return nil
}

// ValidateRelease reports whether a release identifier is usable.
//
// It becomes part of a URL (/v<release>/...), a storage directory name and a
// key, so the character set is narrow on purpose - this is the one string that
// crosses all three.
func ValidateRelease(release string) error {
	if release == "" {
		return errors.New("bundle: the manifest declares no release")
	}

	if len(release) > MaxReleaseLen {
		return fmt.Errorf("bundle: release %q is %d bytes, the limit is %d",
			release, len(release), MaxReleaseLen)
	}

	if !pathSegment.MatchString(release) {
		return fmt.Errorf(
			"bundle: release %q may only contain letters, digits, '.', '_' and '-'", release)
	}

	// A release is a path segment in a URL and a directory name, so neither
	// dot form may appear alone.
	if release == "." || release == ".." {
		return fmt.Errorf("bundle: release %q is not a usable identifier", release)
	}

	return nil
}

// validateArchivePath checks a manifest's reference to a file in the archive.
//
// This is the manifest side of the zip-slip defence. extract.go rejects
// hostile entry names as it unpacks; this rejects a manifest that points
// outside the bundle even when every entry in the archive was benign.
func validateArchivePath(file string) error {
	if file == "" {
		return errors.New("file is empty")
	}

	if strings.HasPrefix(file, "/") {
		return fmt.Errorf("file %q must be relative to the archive root", file)
	}

	if strings.Contains(file, `\`) {
		return fmt.Errorf("file %q must use '/' as its separator", file)
	}

	if cleaned := path.Clean(file); cleaned != file {
		return fmt.Errorf("file %q is not canonical, use %q", file, cleaned)
	}

	for _, segment := range strings.Split(file, "/") {
		if segment == ".." {
			return fmt.Errorf("file %q escapes the archive root", file)
		}

		if segment == "" || segment == "." {
			return fmt.Errorf("file %q contains an empty or '.' segment", file)
		}
	}

	return nil
}

// ContentTypeFor returns the Content-Type to serve for a route.
//
// An explicit manifest value always wins. Otherwise it is inferred from the
// extension, falling back to text/plain rather than
// application/octet-stream: these are scripts, and a browser offering to
// download an installer is less useful than showing it, which is also what
// lets a cautious user read before piping.
func (r *Route) ContentTypeFor() string {
	if r.ContentType != "" {
		return r.ContentType
	}

	switch strings.ToLower(path.Ext(r.Path)) {
	case ".sh", ".bash":
		return "text/x-shellscript; charset=utf-8"
	case ".ps1":
		return "text/plain; charset=utf-8"
	case ".py":
		return "text/x-python; charset=utf-8"
	case ".json":
		return "application/json"
	default:
		return "text/plain; charset=utf-8"
	}
}

// ChecksumPath returns the path a route's SHA-256 is served at.
func (r *Route) ChecksumPath() string { return r.Path + ChecksumSuffix }
