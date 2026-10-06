package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/adnoctem/netory/internal/signpost/bundle"
)

// Resolution is what the serving path needs to answer one request.
type Resolution struct {
	// Route is the published route being served.
	Route PublishedRoute

	// Release is which release it came from.
	Release string

	// Versioned reports whether the request came in on a /v<release>/ path,
	// which decides the cache lifetime (§5.2).
	Versioned bool

	// Checksum reports whether the request was for the route's `.sha256`
	// sibling rather than the route itself.
	Checksum bool
}

// RouteTable is an immutable snapshot of everything the public listener serves.
//
// Immutable and swapped whole. The serving path reads it through an
// atomic.Pointer and never takes a lock, so a publish cannot make a request
// wait, and - more importantly - a request can never observe a table that is
// half-rebuilt. That is the other half of §2's atomic alias swap: the swap is
// atomic in the database, and what the server serves changes atomically too.
//
// It holds metadata only. Content is fetched from Storage on demand, so the
// table's size is bounded by the number of routes rather than by their bytes.
type RouteTable struct {
	// Alias is the serving alias, and Release what it pointed at when the
	// table was built. Both empty when nothing is published yet.
	Alias   string
	Release string

	// routes maps a request path to a route of the serving release.
	routes map[string]PublishedRoute

	// versioned maps a release to its routes, for the /v<release>/ paths.
	//
	// Every release rather than only the served one, and deliberately: a
	// versioned request would otherwise need a database read on the public
	// listener, which is the one listener an anonymous client can aim traffic
	// at. Metadata for a few hundred releases is kilobytes; a database read
	// per request is a lever.
	versioned map[string]map[string]PublishedRoute

	// GeneratedAt is when the snapshot was built, for diagnostics.
	GeneratedAt time.Time

	// serveVersioned mirrors the setting, captured at build time so the
	// serving path does not read settings per request.
	serveVersioned bool
}

// EmptyRouteTable returns a table that serves nothing.
//
// Used before the first publish and after the serving alias is removed. It
// serves 404s rather than failing, because a signpost with nothing published
// is a correctly configured service that has nothing to say yet.
func EmptyRouteTable() *RouteTable {
	return &RouteTable{
		routes:      map[string]PublishedRoute{},
		versioned:   map[string]map[string]PublishedRoute{},
		GeneratedAt: time.Now().UTC(),
	}
}

// Len returns how many alias routes the table serves.
func (t *RouteTable) Len() int { return len(t.routes) }

// Paths returns the served alias paths, sorted. For diagnostics and the admin
// API; the serving path does not use it.
func (t *RouteTable) Paths() []string {
	paths := make([]string, 0, len(t.routes))
	for path := range t.routes {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	return paths
}

// Releases returns the releases reachable on versioned paths, sorted.
func (t *RouteTable) Releases() []string {
	releases := make([]string, 0, len(t.versioned))
	for release := range t.versioned {
		releases = append(releases, release)
	}
	sort.Strings(releases)

	return releases
}

// Resolve maps a request path to a route.
//
// The order is: strip a `.sha256` suffix, then try the versioned prefix, then
// the alias routes. Checksums are resolved first because `.sha256` is a suffix
// on the path rather than a path of its own - a route and its checksum are the
// same route, served differently.
func (t *RouteTable) Resolve(requestPath string) (Resolution, bool) {
	checksum := false
	if trimmed, ok := strings.CutSuffix(requestPath, bundle.ChecksumSuffix); ok {
		checksum = true
		requestPath = trimmed
	}

	if t.serveVersioned {
		if release, rest, ok := splitVersioned(requestPath); ok {
			routes, known := t.versioned[release]
			if !known {
				return Resolution{}, false
			}

			route, found := routes[rest]
			if !found {
				return Resolution{}, false
			}

			return Resolution{
				Route:     route,
				Release:   release,
				Versioned: true,
				Checksum:  checksum,
			}, true
		}
	}

	route, found := t.routes[requestPath]
	if !found {
		return Resolution{}, false
	}

	return Resolution{Route: route, Release: t.Release, Checksum: checksum}, true
}

// splitVersioned separates a /v<release>/<path> request into its parts.
//
// The release is matched by the same rule manifest validation rejects as a
// first route segment, so the two cannot disagree about which paths are
// versioned - a bundle can never publish a route that this function would
// claim first.
func splitVersioned(requestPath string) (release, rest string, ok bool) {
	if !strings.HasPrefix(requestPath, "/") {
		return "", "", false
	}

	first, remainder, found := strings.Cut(requestPath[1:], "/")
	if !found || first == "" || remainder == "" {
		return "", "", false
	}

	if !bundle.IsVersionedSegment(first) {
		return "", "", false
	}

	// The leading "v" is the marker, not part of the release identifier:
	// release 1.4.0 is served at /v1.4.0/.
	return strings.TrimPrefix(first, "v"), "/" + remainder, true
}

// VersionedPath renders where a release's route is served for pinned installs.
func VersionedPath(release, routePath string) string {
	return "/v" + release + routePath
}

// buildRouteTable assembles a snapshot from the current database contents.
//
// Built from a read of every release rather than incrementally patched, for
// the usual reason: a snapshot rebuilt from the source of truth cannot drift
// from it, and a publish is rare enough that the cost of rebuilding is paid in
// a place nobody is waiting.
func (s *State) buildRouteTable(ctx context.Context) (*RouteTable, error) {
	settings, err := s.Settings.Load(ctx)
	if err != nil {
		return nil, err
	}

	releases, err := s.Releases.List(ctx)
	if err != nil {
		return nil, err
	}

	table := &RouteTable{
		Alias:          settings.ServeAlias,
		routes:         map[string]PublishedRoute{},
		versioned:      map[string]map[string]PublishedRoute{},
		GeneratedAt:    time.Now().UTC(),
		serveVersioned: settings.ServeVersioned,
	}

	for _, release := range releases {
		routes := make(map[string]PublishedRoute, len(release.Routes))
		for _, route := range release.Routes {
			routes[route.Path] = route
		}

		table.versioned[release.Release] = routes
	}

	alias, err := s.Aliases.Get(ctx, settings.ServeAlias)
	switch {
	case errors.Is(err, ErrAliasNotFound):
		// Nothing published under the serving alias. The versioned routes of
		// any release that does exist stay reachable, which is deliberate: an
		// operator who removed the alias has stopped offering an unversioned
		// install, not retracted the releases.
		return table, nil
	case err != nil:
		return nil, err
	}

	table.Release = alias.Release

	routes, ok := table.versioned[alias.Release]
	if !ok {
		// The alias names a release that is not in the database. Reported
		// rather than served as an empty table, because it means metadata has
		// diverged and serving 404s would hide that.
		return nil, fmt.Errorf(
			"alias %q points at release %q, which is not published",
			alias.Name, alias.Release)
	}

	for path, route := range routes {
		table.routes[path] = route
	}

	return table, nil
}

// Table returns the current route table. Never nil.
func (s *State) Table() *RouteTable {
	if table := s.table.Load(); table != nil {
		return table
	}

	return EmptyRouteTable()
}

// RebuildTable rebuilds the route table and swaps it in.
//
// Called after anything that changes what is served: a publish, an alias move,
// a removal, or a settings change touching serve.alias or serve.versioned. The
// swap is one atomic.Pointer store, so no request sees an intermediate state.
func (s *State) RebuildTable(ctx context.Context) error {
	table, err := s.buildRouteTable(ctx)
	if err != nil {
		return err
	}

	s.table.Store(table)

	s.Log.Debug("route table rebuilt",
		"alias", table.Alias,
		"release", table.Release,
		"routes", table.Len(),
		"releases", len(table.versioned))

	return nil
}

// table is the atomically swapped snapshot. Declared here next to the code
// that uses it rather than in state.go, so the invariant - only RebuildTable
// stores, only Table loads - is visible in one file.
type routeTablePointer = atomic.Pointer[RouteTable]
