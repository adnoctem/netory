package bundle_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/signpost/bundle"
)

// update regenerates the committed schema instead of comparing against it.
//
// Run as `go test ./internal/signpost/bundle -run TestSchema -update` after
// changing the manifest types. The flag is the whole mechanism by which the
// committed file stays in step: there is no way to change the Go types and
// leave the schema stale without this test failing.
var update = flag.Bool("update", false, "rewrite the committed manifest schema")

// schemaPath is where the generated schema is committed, relative to this
// package.
const schemaPath = "../../../docs/schema/signpost-manifest-v1.json"

func TestSchemaMatchesCommittedFile(t *testing.T) {
	t.Parallel()

	generated, err := bundle.Schema()
	require.NoError(t, err)

	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(schemaPath), 0o755))
		require.NoError(t, os.WriteFile(schemaPath, generated, 0o644))
		t.Log("rewrote " + schemaPath)

		return
	}

	committed, err := os.ReadFile(schemaPath)
	require.NoError(t, err,
		"the committed schema is missing: regenerate it with `go test ./internal/signpost/bundle -run TestSchema -update`")

	assert.Equal(t, string(committed), string(generated),
		"the committed schema no longer matches the Go types: "+
			"regenerate it with `go test ./internal/signpost/bundle -run TestSchema -update`")
}

// TestSchemaDescribesEveryField is the guard that makes "generated from the Go
// types" mean something.
//
// Reflection fills in a property for every exported field whether or not
// anyone described it, so without this test a new field would appear in the
// schema as an unconstrained string of the right type and nobody would notice.
// Here, adding a field without declaring its bounds fails.
func TestSchemaDescribesEveryField(t *testing.T) {
	t.Parallel()

	document := decodeSchema(t)

	manifestProps := properties(t, document)
	routeProps := properties(t, defs(t, document)["route"])

	for name, props := range map[string]map[string]any{
		"manifest": manifestProps,
		"route":    routeProps,
	} {
		for field, raw := range props {
			property, ok := raw.(map[string]any)
			require.True(t, ok, "%s.%s is not an object", name, field)

			assert.NotEmpty(t, property["description"],
				"%s.%s has no description: declare it in the constraints table in schema.go",
				name, field)
		}
	}
}

// TestSchemaMatchesStructTags asserts the schema's property set and required
// list are exactly what the Go structs declare.
//
// This is the agreement §9.1 asked for, checked rather than assumed: the
// properties come from the json tags and the required list from the absence of
// omitempty, so a field renamed in Go and not in the schema - or made optional
// in one place only - is caught here.
func TestSchemaMatchesStructTags(t *testing.T) {
	t.Parallel()

	document := decodeSchema(t)

	t.Run("Manifest", func(t *testing.T) {
		t.Parallel()
		assertMatchesType(t, reflect.TypeFor[bundle.Manifest](), document)
	})

	t.Run("Route", func(t *testing.T) {
		t.Parallel()
		assertMatchesType(t, reflect.TypeFor[bundle.Route](), defs(t, document)["route"])
	})
}

// assertMatchesType compares one struct's json tags against one schema object.
func assertMatchesType(t *testing.T, typ reflect.Type, raw any) {
	t.Helper()

	object, ok := raw.(map[string]any)
	require.True(t, ok, "the schema object for %s is missing", typ.Name())

	wantProps := map[string]bool{}
	wantRequired := map[string]bool{}

	for i := range typ.NumField() {
		field := typ.Field(i)

		tag := field.Tag.Get("json")
		require.NotEmpty(t, tag,
			"%s.%s has no json tag, so the schema cannot name it", typ.Name(), field.Name)

		name, options, _ := strings.Cut(tag, ",")
		wantProps[name] = true

		if !strings.Contains(options, "omitempty") {
			wantRequired[name] = true
		}
	}

	gotProps := map[string]bool{}
	for name := range properties(t, object) {
		gotProps[name] = true
	}

	assert.Equal(t, wantProps, gotProps, "%s: the schema's properties differ from the struct's", typ.Name())

	gotRequired := map[string]bool{}

	list, ok := object["required"].([]any)
	require.True(t, ok, "%s: the schema declares no required list", typ.Name())

	for _, entry := range list {
		name, ok := entry.(string)
		require.True(t, ok)
		gotRequired[name] = true
	}

	assert.Equal(t, wantRequired, gotRequired,
		"%s: the schema's required fields differ from the fields without omitempty", typ.Name())

	assert.Equal(t, false, object["additionalProperties"],
		"%s: the schema must reject unknown fields, matching ParseManifest", typ.Name())
}

// TestSchemaCarriesTheValidatorsLimits asserts the schema's numbers are the
// constants the Go validation uses, not copies of them.
func TestSchemaCarriesTheValidatorsLimits(t *testing.T) {
	t.Parallel()

	document := decodeSchema(t)
	manifestProps := properties(t, document)
	routeProps := properties(t, defs(t, document)["route"])

	release, ok := manifestProps["release"].(map[string]any)
	require.True(t, ok)
	assert.InDelta(t, float64(bundle.MaxReleaseLen), release["maxLength"], 0)

	routes, ok := manifestProps["routes"].(map[string]any)
	require.True(t, ok)
	assert.InDelta(t, float64(bundle.MaxRoutes), routes["maxItems"], 0)

	version, ok := manifestProps["version"].(map[string]any)
	require.True(t, ok)
	assert.InDelta(t, float64(bundle.ManifestVersion), version["const"], 0)

	path, ok := routeProps["path"].(map[string]any)
	require.True(t, ok)
	assert.InDelta(t, float64(bundle.MaxPathLen), path["maxLength"], 0)
}

// TestSchemaAgreesOnValidManifests checks the schema's own constraints against
// manifests the Go validation accepts and rejects.
//
// Not a JSON Schema validation - that would be a dependency for one test -
// but a check of the constraints the schema carries against the validator's
// verdict on the same input. Where the two can disagree, they are made to
// agree here: a release the schema's pattern would reject must not be one
// Validate accepts, and vice versa.
func TestSchemaAgreesOnValidManifests(t *testing.T) {
	t.Parallel()

	document := decodeSchema(t)
	releaseProperty, ok := properties(t, document)["release"].(map[string]any)
	require.True(t, ok)

	pattern, ok := releaseProperty["pattern"].(string)
	require.True(t, ok, "the release property declares no pattern")

	maxLength, ok := releaseProperty["maxLength"].(float64)
	require.True(t, ok)

	cases := []string{
		"1.4.0", "v2", "2026-01-01", "a", strings.Repeat("a", bundle.MaxReleaseLen),
		"", "has space", "with/slash", "..", ".", "tab\there",
		strings.Repeat("a", bundle.MaxReleaseLen+1),
	}

	for _, release := range cases {
		t.Run("release="+release, func(t *testing.T) {
			t.Parallel()

			goAccepts := bundle.ValidateRelease(release) == nil
			schemaAccepts := matchesPattern(t, pattern, release) &&
				release != "" &&
				float64(len(release)) <= maxLength &&
				release != "." && release != ".."

			assert.Equal(t, goAccepts, schemaAccepts,
				"the schema and the Go validation disagree about release %q", release)
		})
	}
}

// matchesPattern applies a schema pattern to a value.
func matchesPattern(t *testing.T, pattern, value string) bool {
	t.Helper()

	compiled, err := compilePattern(pattern)
	require.NoError(t, err)

	return compiled.MatchString(value)
}

// decodeSchema generates and decodes the schema.
func decodeSchema(t *testing.T) map[string]any {
	t.Helper()

	raw, err := bundle.Schema()
	require.NoError(t, err)

	var document map[string]any
	require.NoError(t, json.Unmarshal(raw, &document))

	return document
}

// properties returns an object schema's properties.
func properties(t *testing.T, raw any) map[string]any {
	t.Helper()

	object, ok := raw.(map[string]any)
	require.True(t, ok, "not a schema object")

	props, ok := object["properties"].(map[string]any)
	require.True(t, ok, "the schema object declares no properties")

	return props
}

// defs returns the schema's $defs.
func defs(t *testing.T, document map[string]any) map[string]any {
	t.Helper()

	found, ok := document["$defs"].(map[string]any)
	require.True(t, ok, "the schema declares no $defs")

	return found
}
