package bundle

import (
	"maps"
	"reflect"
	"strconv"

	"github.com/adnoctem/netory/pkg/schema"
)

// SchemaName is the committed schema's file name under docs/schema.
const SchemaName = "signpost-manifest-v1.json"

// SchemaID is the manifest schema's identifier.
//
// Versioned by the manifest version it describes, so publishing a version 2
// schema does not invalidate a tool pinned to this one. The base it is built
// from lives in pkg/schema, so moving where the schemas are served is one
// edit rather than one per service.
var SchemaID = schema.ID(SchemaName)

// SchemaDialect is the JSON Schema dialect the generated document declares.
const SchemaDialect = schema.Dialect

// Schema returns the manifest's JSON Schema, generated from the Go types.
//
// Generated rather than written, and that is the resolution of §9.1 rather
// than an implementation detail of it. The Go validation in this file is what
// actually runs at publish time, so a schema maintained beside it would be a
// second description of the same thing, free to drift the moment someone adds
// a field. Deriving it means the property names, their types and which ones
// are required come from the structs themselves, and the bounds and patterns
// come from the same constants and regexps Validate uses. The committed
// document under docs/schema is this function's output, and a test fails if
// the two differ.
//
// What the schema deliberately does not express: reserved paths, route-path
// uniqueness, that every route's file exists in the archive, and the
// truncation check. Those are not expressible in JSON Schema, or depend on the
// archive rather than the manifest. A manifest that satisfies this schema is
// well-formed, not publishable - which is why the server validates in Go and
// the schema is for editors and CI.
func Schema() ([]byte, error) {
	document := map[string]any{
		"$schema":     SchemaDialect,
		"$id":         SchemaID,
		"title":       "signpost bundle manifest",
		"description": schemaDescription,
		"type":        "object",
		"$defs": map[string]any{
			"route": schema.Object(reflect.TypeFor[Route](), routeConstraints),
		},
	}

	maps.Copy(document, schema.Object(reflect.TypeFor[Manifest](), manifestConstraints))

	return schema.Encode(document)
}

// schemaDescription is the prose at the top of the generated document.
const schemaDescription = "A signpost bundle's manifest, at the root of a .zip or .tar.gz archive as " +
	"signpost.yaml, signpost.yml or signpost.json. Satisfying this schema means the manifest is " +
	"well-formed; signpost applies further checks at publish time that JSON Schema cannot express, " +
	"including reserved paths, route uniqueness, that every referenced file is in the archive, and " +
	"the truncation-protection check on every script."

// manifestConstraints describes Manifest's fields.
var manifestConstraints = map[string]schema.Property{
	"version": {
		Description: "The manifest schema version. Only " +
			jsonNumber(ManifestVersion) + " is understood by this build.",
		Constraints: map[string]any{
			"type":  "integer",
			"const": ManifestVersion,
		},
	},
	"release": {
		Description: "This bundle's identifier, unique per signpost instance. It becomes a URL " +
			"segment (/v<release>/...), a storage directory name and a database key, which is why " +
			"the character set is narrow.",
		Constraints: map[string]any{
			"type":      "string",
			"minLength": 1,
			"maxLength": MaxReleaseLen,
			"pattern":   pathSegment.String(),
		},
	},
	"description": {
		Description: "An optional note shown by `signpost bundle list`.",
		Constraints: map[string]any{"type": "string"},
	},
	"routes": {
		Description: "The paths this bundle serves. Each one is also served with a .sha256 suffix " +
			"carrying its checksum, and at /v<release>/<path> for pinned installs.",
		Constraints: map[string]any{
			"type":     "array",
			"minItems": 1,
			"maxItems": MaxRoutes,
			"items":    map[string]any{"$ref": "#/$defs/route"},
		},
	},
}

// routeConstraints describes Route's fields.
var routeConstraints = map[string]schema.Property{
	"path": {
		Description: "The URL path to serve at, beginning with '/' and already canonical. It may " +
			"not end in .sha256, may not be the server's health path, and its first segment may " +
			"not look like /v<release>/ - all three are reserved by the server.",
		Constraints: map[string]any{
			"type":      "string",
			"minLength": 2,
			"maxLength": MaxPathLen,
			"pattern":   `^/[A-Za-z0-9._/-]+$`,
			"not":       map[string]any{"pattern": `\` + ChecksumSuffix + `$`},
		},
	},
	"file": {
		Description: "The file inside the archive, relative to its root, using '/' as the " +
			"separator. It may not be absolute and may not escape the archive.",
		Constraints: map[string]any{
			"type":      "string",
			"minLength": 1,
			"pattern":   `^[^/\\][^\\]*$`,
		},
	},
	"content_type": {
		Description: "The Content-Type to serve. Optional; inferred from the file extension when " +
			"absent, falling back to text/plain so a script can be read before it is piped.",
		Constraints: map[string]any{
			"type":      "string",
			"minLength": 1,
		},
	},
	"skip_truncation_check": {
		Description: "Opts this one route out of the truncation-protection check. The check is a " +
			"heuristic over shell and PowerShell syntax and will occasionally be wrong about a " +
			"legitimate script, so the escape hatch exists - but it is recorded on the release, " +
			"reported by `bundle list` and carried in the publish event, and an instance may " +
			"refuse it outright.",
		Constraints: map[string]any{
			"type":    "boolean",
			"default": false,
		},
	},
}

// jsonNumber renders an int for the generated prose.
func jsonNumber(value int) string { return strconv.Itoa(value) }
