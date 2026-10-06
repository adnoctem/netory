package bundle_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/signpost/bundle"
)

// manifestFor builds a minimal manifest around one route.
func manifestFor(route bundle.Route) *bundle.Manifest {
	return &bundle.Manifest{
		Version: bundle.ManifestVersion,
		Release: "1.0.0",
		Routes:  []bundle.Route{route},
	}
}

func TestManifestAccepts(t *testing.T) {
	asrt := assert.New(t)

	for name, route := range map[string]bundle.Route{
		"simple":            {Path: "/install.sh", File: "scripts/install.sh"},
		"nested path":       {Path: "/tools/setup/install.sh", File: "install.sh"},
		"no extension":      {Path: "/install", File: "install"},
		"explicit type":     {Path: "/install.sh", File: "i.sh", ContentType: "text/x-shellscript"},
		"type with charset": {Path: "/i.sh", File: "i.sh", ContentType: "text/plain; charset=utf-8"},
		"root file":         {Path: "/install.sh", File: "install.sh"},
		"skip opt-out":      {Path: "/i.sh", File: "i.sh", SkipTruncationCheck: true},
	} {
		asrt.NoError(manifestFor(route).Validate(), name)
	}
}

// Reserved paths: a route may not shadow the server's own paths or the derived
// ones it serves. Shadowing /healthz would make the service look unhealthy,
// and shadowing a .sha256 path would make a checksum lie about which bytes it
// covers.
func TestManifestRejectsReservedPaths(t *testing.T) {
	asrt := assert.New(t)

	for name, path := range map[string]string{
		"the health endpoint":   "/healthz",
		"a checksum path":       "/install.sh.sha256",
		"a bare checksum path":  "/thing.sha256",
		"the versioned prefix":  "/v1.4.0/install.sh",
		"a versioned-looking v": "/v2/install.sh",
	} {
		err := manifestFor(bundle.Route{Path: path, File: "i.sh"}).Validate()
		asrt.Error(err, name)
	}

	// A first segment starting with 'v' but not a version is fine: only the
	// /v<digit> shape is reserved.
	asrt.NoError(manifestFor(bundle.Route{Path: "/vendor/install.sh", File: "i.sh"}).Validate())
	asrt.NoError(manifestFor(bundle.Route{Path: "/verify.sh", File: "i.sh"}).Validate())
}

func TestManifestRejectsBadPaths(t *testing.T) {
	asrt := assert.New(t)

	for name, path := range map[string]string{
		"empty":            "",
		"no leading slash": "install.sh",
		"not canonical":    "/a/../install.sh",
		"trailing slash":   "/install.sh/",
		"double slash":     "/a//install.sh",
		"a dot segment":    "/./install.sh",
		"a space":          "/install script.sh",
		"a query":          "/install.sh?x=1",
		"a fragment":       "/install.sh#frag",
		"percent encoded":  "/install%2Esh",
		"too long":         "/" + strings.Repeat("a", bundle.MaxPathLen),
	} {
		err := manifestFor(bundle.Route{Path: path, File: "i.sh"}).Validate()
		asrt.Error(err, "%s (%q)", name, path)
	}
}

// The manifest side of the zip-slip defence: a manifest that points outside
// the bundle is refused even when every archive entry was benign.
func TestManifestRejectsBadFileReferences(t *testing.T) {
	asrt := assert.New(t)

	for name, file := range map[string]string{
		"empty":            "",
		"absolute":         "/etc/passwd",
		"traversal":        "../outside.sh",
		"nested traversal": "scripts/../../outside.sh",
		"not canonical":    "scripts/./install.sh",
		"backslash":        `scripts\install.sh`,
		"trailing slash":   "scripts/",
	} {
		err := manifestFor(bundle.Route{Path: "/install.sh", File: file}).Validate()
		asrt.Error(err, "%s (%q)", name, file)
	}
}

func TestManifestRejectsBadVersionAndRelease(t *testing.T) {
	asrt := assert.New(t)

	// A manifest written for a future version is rejected with a message
	// saying so, not read with fields silently missing.
	m := manifestFor(bundle.Route{Path: "/i.sh", File: "i.sh"})
	m.Version = 2
	err := m.Validate()
	asrt.ErrorIs(err, bundle.ErrUnsupportedVersion)
	asrt.Contains(err.Error(), "understands 1")

	m.Version = 0
	asrt.Error(m.Validate())

	for name, release := range map[string]string{
		"empty":        "",
		"with a slash": "1.0/0",
		"with a space": "1.0 beta",
		"dot":          ".",
		"dot dot":      "..",
		"too long":     strings.Repeat("1", bundle.MaxReleaseLen+1),
	} {
		asrt.Error(bundle.ValidateRelease(release), "%s (%q)", name, release)
	}

	for _, release := range []string{"1.0.0", "1.4.0-rc.1", "v1.2.3", "2026.10.09", "nightly"} {
		asrt.NoError(bundle.ValidateRelease(release), release)
	}
}

// A manifest declaring one path twice is ambiguous about which file it serves,
// and guessing would be worse than refusing.
func TestManifestRejectsDuplicatePaths(t *testing.T) {
	asrt := assert.New(t)

	m := &bundle.Manifest{
		Version: bundle.ManifestVersion,
		Release: "1.0.0",
		Routes: []bundle.Route{
			{Path: "/install.sh", File: "a.sh"},
			{Path: "/install.sh", File: "b.sh"},
		},
	}

	err := m.Validate()
	asrt.Error(err)
	asrt.Contains(err.Error(), "duplicates")
	asrt.Contains(err.Error(), "route 0", "the error must name both offending routes")
}

func TestManifestRejectsEmptyAndOversizedRouteLists(t *testing.T) {
	asrt := assert.New(t)

	empty := &bundle.Manifest{Version: bundle.ManifestVersion, Release: "1.0.0"}
	asrt.Error(empty.Validate())

	routes := make([]bundle.Route, bundle.MaxRoutes+1)
	for i := range routes {
		routes[i] = bundle.Route{Path: "/r" + itoa(i) + ".sh", File: "i.sh"}
	}

	tooMany := &bundle.Manifest{Version: bundle.ManifestVersion, Release: "1.0.0", Routes: routes}
	err := tooMany.Validate()
	asrt.Error(err)
	asrt.Contains(err.Error(), "limit")
}

// An error must name the offending route, because a rejected bundle is
// rejected whole and the operator needs to know which entry to fix.
func TestManifestErrorsNameTheRoute(t *testing.T) {
	asrt := assert.New(t)

	m := &bundle.Manifest{
		Version: bundle.ManifestVersion,
		Release: "1.0.0",
		Routes: []bundle.Route{
			{Path: "/good.sh", File: "good.sh"},
			{Path: "/healthz", File: "bad.sh"},
		},
	}

	err := m.Validate()
	require.Error(t, err)
	asrt.Contains(err.Error(), "route 1")
	asrt.Contains(err.Error(), "/healthz")
}

// Both decoders reject unknown fields. A manifest with a mistyped key would
// otherwise publish successfully and then serve the wrong Content-Type, which
// is exactly the silent failure this service cannot afford.
func TestParseManifestRejectsUnknownFields(t *testing.T) {
	asrt := assert.New(t)

	_, err := bundle.ParseManifest("signpost.yaml", []byte(`version: 1
release: 1.0.0
routes:
  - path: /install.sh
    file: install.sh
    content-type: text/plain
`))
	asrt.Error(err, "a hyphenated key must not be silently ignored")

	_, err = bundle.ParseManifest("signpost.json", []byte(
		`{"version":1,"release":"1.0.0","routes":[{"path":"/i.sh","file":"i.sh","contentType":"text/plain"}]}`))
	asrt.Error(err, "a camelCase key must not be silently ignored")
}

func TestParseManifestFormats(t *testing.T) {
	asrt := assert.New(t)

	yamlManifest, err := bundle.ParseManifest("signpost.yaml", []byte(goodManifest))
	require.NoError(t, err)
	asrt.Equal("1.4.0", yamlManifest.Release)

	// .yml is accepted as well as .yaml.
	_, err = bundle.ParseManifest("signpost.yml", []byte(goodManifest))
	asrt.NoError(err)

	jsonManifest, err := bundle.ParseManifest("signpost.json",
		[]byte(`{"version":1,"release":"2.0.0","routes":[{"path":"/i.sh","file":"i.sh"}]}`))
	require.NoError(t, err)
	asrt.Equal("2.0.0", jsonManifest.Release)

	// YAML and JSON must map onto the same shape.
	asrt.Equal(yamlManifest.Routes[0].Path, "/install.sh")

	for name, input := range map[string]string{
		"empty":         "",
		"not yaml":      "\tthis: is: not: yaml:\n  - [",
		"two documents": goodManifest + "---\n" + goodManifest,
	} {
		_, err := bundle.ParseManifest("signpost.yaml", []byte(input))
		asrt.Error(err, name)
	}

	_, err = bundle.ParseManifest("signpost.json", []byte("{not json"))
	asrt.Error(err)

	_, err = bundle.ParseManifest("signpost.toml", []byte("x = 1"))
	asrt.Error(err)
}

// The inferred Content-Type falls back to text/plain rather than
// application/octet-stream: these are scripts, and a browser offering to
// download an installer is less useful than showing it - which is also what
// lets a cautious user read before piping.
func TestContentTypeInference(t *testing.T) {
	asrt := assert.New(t)

	for path, want := range map[string]string{
		"/install.sh":  "text/x-shellscript; charset=utf-8",
		"/install.ps1": "text/plain; charset=utf-8",
		"/setup.py":    "text/x-python; charset=utf-8",
		"/meta.json":   "application/json",
		"/install":     "text/plain; charset=utf-8",
	} {
		route := bundle.Route{Path: path, File: "f"}
		asrt.Equal(want, route.ContentTypeFor(), path)
	}

	// An explicit value always wins.
	explicit := bundle.Route{Path: "/install.sh", File: "f", ContentType: "application/x-custom"}
	asrt.Equal("application/x-custom", explicit.ContentTypeFor())
}

func TestChecksumPath(t *testing.T) {
	route := bundle.Route{Path: "/install.sh", File: "f"}
	assert.Equal(t, "/install.sh.sha256", route.ChecksumPath())
}
