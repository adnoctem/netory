package rules_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/rules"
)

// update regenerates the committed schema instead of comparing against it.
//
// Run as `go test ./internal/pivot/rules -run TestSchema -update` after
// changing the rule document types. The flag is the whole mechanism by which
// the committed file stays in step: there is no way to change the Go types and
// leave the schema stale without this test failing.
var update = flag.Bool("update", false, "rewrite the committed rule schema")

// schemaPath is where the generated schema is committed, relative to this
// package.
const schemaPath = "../../../docs/schema/pivot-rules-v1.json"

func TestSchemaMatchesCommittedFile(t *testing.T) {
	t.Parallel()

	generated, err := rules.Schema()
	require.NoError(t, err)

	if *update {
		require.NoError(t, os.MkdirAll(filepath.Dir(schemaPath), 0o755))
		require.NoError(t, os.WriteFile(schemaPath, generated, 0o644))
		t.Log("rewrote " + schemaPath)

		return
	}

	committed, err := os.ReadFile(schemaPath)
	require.NoError(t, err,
		"the committed schema is missing: regenerate it with `go test ./internal/pivot/rules -run TestSchema -update`")

	assert.Equal(t, string(committed), string(generated),
		"the committed schema no longer matches the Go types: "+
			"regenerate it with `go test ./internal/pivot/rules -run TestSchema -update`")
}

// TestSchemaDescribesEveryField is the guard that makes "generated from the Go
// types" mean something.
//
// Reflection fills in a property for every exported field whether or not
// anyone described it, so without this test a new field would appear in the
// schema as an unconstrained value of the right type and nobody would notice.
// Here, adding a field without declaring its bounds fails.
func TestSchemaDescribesEveryField(t *testing.T) {
	t.Parallel()

	document := decodeSchema(t)
	definitions := defs(t, document)

	objects := map[string]map[string]any{
		"document":  properties(t, document),
		"rules":     properties(t, definitions["rules"]),
		"denyRule":  properties(t, definitions["denyRule"]),
		"allowRule": properties(t, definitions["allowRule"]),
		"route":     properties(t, definitions["route"]),
		"cache":     properties(t, definitions["cache"]),
	}

	for name, props := range objects {
		for field, raw := range props {
			property, ok := raw.(map[string]any)
			require.True(t, ok, "%s.%s is not an object", name, field)

			assert.NotEmpty(t, property["description"],
				"%s.%s has no description: declare it in the constraints table in schema.go",
				name, field)
		}
	}
}

// TestSchemaMatchesStructTags asserts the schema's shape is the structs'
// shape, since that is the claim "generated from the Go types" makes.
func TestSchemaMatchesStructTags(t *testing.T) {
	t.Parallel()

	document := decodeSchema(t)
	definitions := defs(t, document)

	for name, pair := range map[string]struct {
		typ    reflect.Type
		object any
	}{
		"Document":  {reflect.TypeFor[rules.Document](), document},
		"RuleLists": {reflect.TypeFor[rules.RuleLists](), definitions["rules"]},
		"Rule":      {reflect.TypeFor[rules.Rule](), definitions["denyRule"]},
		"Route":     {reflect.TypeFor[rules.Route](), definitions["route"]},
		"Cache":     {reflect.TypeFor[rules.Cache](), definitions["cache"]},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertMatchesStruct(t, pair.typ, pair.object)
		})
	}
}

func assertMatchesStruct(t *testing.T, typ reflect.Type, object any) {
	t.Helper()

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

	assert.Equal(t, wantProps, gotProps,
		"%s: the schema's properties differ from the struct's", typ.Name())

	gotRequired := map[string]bool{}

	entry, ok := object.(map[string]any)
	require.True(t, ok)

	// A missing list is how an object with no required fields is spelled, so
	// its absence is only wrong when the struct has a field without omitempty.
	if list, ok := entry["required"].([]any); ok {
		for _, name := range list {
			text, ok := name.(string)
			require.True(t, ok)
			gotRequired[text] = true
		}
	}

	assert.Equal(t, wantRequired, gotRequired,
		"%s: the schema's required fields differ from the fields without omitempty", typ.Name())

	assert.Equal(t, false, entry["additionalProperties"],
		"%s: the schema must reject unknown fields, matching Parse", typ.Name())
}

// TestSchemaCarriesTheValidatorsLimits asserts the schema's numbers are the
// constants the compiler uses, not copies of them.
func TestSchemaCarriesTheValidatorsLimits(t *testing.T) {
	t.Parallel()

	document := decodeSchema(t)
	definitions := defs(t, document)

	routes, ok := properties(t, document)["routes"].(map[string]any)
	require.True(t, ok)
	assert.InDelta(t, float64(rules.MaxRules), routes["maxItems"], 0)

	for _, list := range []string{"deny", "allow"} {
		entry, ok := properties(t, definitions["rules"])[list].(map[string]any)
		require.True(t, ok)
		assert.InDelta(t, float64(rules.MaxRules), entry["maxItems"], 0,
			"the %s list does not carry MaxRules", list)
	}
}

// TestSchemaAgreesOnMethods checks the generated method pattern against the
// compiler's verdict on the same tokens.
//
// Not a JSON Schema validation - that would be a dependency for one test - but
// a check of the constraint the schema carries against what pivot accepts. The
// pattern is generated from ForwardableMethods and has to stay exactly as
// permissive as compileMethods, including about case: the compiler upper-cases
// what it reads, so a schema that rejected `get` would mark a working document
// as wrong.
func TestSchemaAgreesOnMethods(t *testing.T) {
	t.Parallel()

	document := decodeSchema(t)
	definitions := defs(t, document)

	for _, test := range []struct {
		list  string
		def   string
		token string
		valid bool
	}{
		{"allow", "allowRule", "GET", true},
		{"allow", "allowRule", "get", true},
		{"allow", "allowRule", "Get", true},
		{"allow", "allowRule", "HEAD", true},
		{"allow", "allowRule", "POST", true},
		{"allow", "allowRule", "PUT", false},
		{"allow", "allowRule", "DELETE", false},
		{"allow", "allowRule", "OPTIONS", false},
		{"allow", "allowRule", "", false},
		// The wildcard is a deny-only token, and the two definitions exist to
		// say so in a way an editor can act on.
		{"allow", "allowRule", "*", false},
		{"deny", "denyRule", "*", true},
		{"deny", "denyRule", "GET", true},
		{"deny", "denyRule", "PUT", false},
	} {
		t.Run(test.def+"/"+test.token, func(t *testing.T) {
			t.Parallel()

			methods, ok := properties(t, definitions[test.def])["methods"].(map[string]any)
			require.True(t, ok)

			items, ok := methods["items"].(map[string]any)
			require.True(t, ok)

			pattern, ok := items["pattern"].(string)
			require.True(t, ok, "the methods property declares no pattern")

			assert.Equal(t, test.valid, matches(t, pattern, test.token),
				"the schema and the compiler disagree about %q in an %s rule", test.token, test.list)

			// And the compiler's own verdict on the same token, so the two
			// cannot drift apart silently.
			assert.Equal(t, test.valid, compiles(t, test.list, test.token, "/api/product"),
				"the compiler's verdict on %q in an %s rule is not the schema's",
				test.token, test.list)
		})
	}
}

// TestSchemaAgreesOnGlobs checks the glob constraints against validateGlob's
// verdict on the same patterns.
func TestSchemaAgreesOnGlobs(t *testing.T) {
	t.Parallel()

	document := decodeSchema(t)
	glob, ok := properties(t, defs(t, document)["denyRule"])["glob"].(map[string]any)
	require.True(t, ok)

	for _, test := range []struct {
		pattern string
		valid   bool
	}{
		{"/api/product", true},
		{"/api/**", true},
		{"/api/search/*", true},
		{"/", true},
		{"api/product", false},   // not absolute
		{"/api/product/", false}, // a normalized path never ends in /
		{`/api\product`, false},  // backslash
		{"/api/**/x", true},
		{"/api/x**", false}, // ** must be a whole segment
		{"/api/***", false}, // *** has no meaning
		{"", false},
	} {
		t.Run(test.pattern, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.valid, matchesGlobConstraints(t, glob, test.pattern),
				"the schema's verdict on %q is not the compiler's", test.pattern)

			assert.Equal(t, test.valid, compiles(t, "deny", "*", test.pattern),
				"the compiler's verdict on %q is not the schema's", test.pattern)
		})
	}
}

// matchesGlobConstraints applies the glob property's pattern and its negated
// alternatives, which together are what an editor would enforce.
func matchesGlobConstraints(t *testing.T, glob map[string]any, value string) bool {
	t.Helper()

	if length, ok := glob["minLength"].(float64); ok && len(value) < int(length) {
		return false
	}

	pattern, ok := glob["pattern"].(string)
	require.True(t, ok, "the glob property declares no pattern")

	if !matches(t, pattern, value) {
		return false
	}

	not, ok := glob["not"].(map[string]any)
	require.True(t, ok, "the glob property declares no negated alternatives")

	alternatives, ok := not["anyOf"].([]any)
	require.True(t, ok)

	for _, raw := range alternatives {
		entry, ok := raw.(map[string]any)
		require.True(t, ok)

		forbidden, ok := entry["pattern"].(string)
		require.True(t, ok)

		if matches(t, forbidden, value) {
			return false
		}
	}

	return true
}

// compiles reports whether pivot accepts a one-rule document.
//
// The compiler is the thing that decides, so the schema's claims are checked
// against it rather than against a second description of the same rules.
func compiles(t *testing.T, list, method, glob string) bool {
	t.Helper()

	rule := rules.Rule{Methods: []string{method}, Glob: glob}

	var document rules.Document
	if list == "deny" {
		document.Rules.Deny = []rules.Rule{rule}
	} else {
		document.Rules.Allow = []rules.Rule{rule}
	}

	_, err := rules.Compile(document, rules.ScopeGlobal)

	return err == nil
}

// matches reports whether a schema pattern matches a value.
func matches(t *testing.T, pattern, value string) bool {
	t.Helper()

	compiled, err := regexp.Compile(pattern)
	require.NoError(t, err)

	return compiled.MatchString(value)
}

// decodeSchema generates and decodes the schema.
func decodeSchema(t *testing.T) map[string]any {
	t.Helper()

	raw, err := rules.Schema()
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
