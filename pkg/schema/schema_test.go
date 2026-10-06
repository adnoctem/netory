package schema_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/schema"
)

// sample covers every shape Object has to get right: a required field, an
// optional one, one renamed by its tag, one excluded, and an unexported one.
type sample struct {
	Name     string `json:"name"`
	Count    int    `json:"count,omitempty"`
	Nested   nested `json:"nested"`
	Excluded string `json:"-"`
	hidden   string //nolint:unused // present to prove it is skipped
}

type nested struct {
	Flag bool `json:"flag,omitempty"`
}

func TestIDIsBuiltFromOneBase(t *testing.T) {
	t.Parallel()

	assert.Equal(t, schema.BaseURL+"/thing-v1.json", schema.ID("thing-v1.json"))
}

func TestObjectDerivesItsShapeFromTheTags(t *testing.T) {
	t.Parallel()

	object := schema.Object(reflect.TypeFor[sample](), nil)

	properties, ok := object["properties"].(map[string]any)
	require.True(t, ok)

	assert.ElementsMatch(t, []string{"name", "count", "nested"}, keys(properties),
		`a json:"-" field and an unexported one are not properties`)

	// Required comes from the absence of omitempty, so there is no second
	// list to keep in step with the struct.
	assert.Equal(t, []string{"name", "nested"}, object["required"])

	assert.Equal(t, false, object["additionalProperties"],
		"both parsers reject unknown fields, so the schema must too")
}

func TestObjectOmitsAnEmptyRequiredList(t *testing.T) {
	t.Parallel()

	object := schema.Object(reflect.TypeFor[nested](), nil)

	_, found := object["required"]
	assert.False(t, found,
		`"required": null is not a valid schema, so an all-optional object declares no list`)
}

func TestObjectFallsBackToTheGoType(t *testing.T) {
	t.Parallel()

	properties, ok := schema.Object(reflect.TypeFor[sample](), nil)["properties"].(map[string]any)
	require.True(t, ok)

	for name, want := range map[string]string{
		"name":   "string",
		"count":  "integer",
		"nested": "object",
	} {
		property, ok := properties[name].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, want, property["type"], "%s got the wrong derived type", name)
	}
}

// TestObjectYieldsToAnExplicitShape is a regression test.
//
// A `oneOf` over a string and an integer with a derived `"type": "integer"`
// added beside it rejects the string, because both keywords apply - which is
// how pivot's `ttl: 5m` came to be refused by a schema written to allow it.
func TestObjectYieldsToAnExplicitShape(t *testing.T) {
	t.Parallel()

	for name, constraints := range map[string]map[string]any{
		"$ref":  {"$ref": "#/$defs/thing"},
		"oneOf": {"oneOf": []any{map[string]any{"type": "string"}}},
		"anyOf": {"anyOf": []any{map[string]any{"type": "string"}}},
		"allOf": {"allOf": []any{map[string]any{"type": "string"}}},
		"const": {"const": 1},
		"enum":  {"enum": []any{"a"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			object := schema.Object(reflect.TypeFor[sample](), map[string]schema.Property{
				"count": {Description: "described", Constraints: constraints},
			})

			properties, ok := object["properties"].(map[string]any)
			require.True(t, ok)

			property, ok := properties["count"].(map[string]any)
			require.True(t, ok)

			_, found := property["type"]
			assert.False(t, found, "%s already says what the property accepts", name)
		})
	}
}

func TestObjectMergesConstraintsAndDescription(t *testing.T) {
	t.Parallel()

	object := schema.Object(reflect.TypeFor[sample](), map[string]schema.Property{
		"name": {
			Description: "the thing's name",
			Constraints: map[string]any{"type": "string", "maxLength": 8},
		},
	})

	properties, ok := object["properties"].(map[string]any)
	require.True(t, ok)

	property, ok := properties["name"].(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "the thing's name", property["description"])
	assert.Equal(t, 8, property["maxLength"])
	assert.Equal(t, "string", property["type"])
}

func TestFieldsNamesEveryEncodedField(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{"count", "name", "nested"}, schema.Fields(reflect.TypeFor[sample]()))
}

func TestEncodeIsReadable(t *testing.T) {
	t.Parallel()

	encoded, err := schema.Encode(map[string]any{
		"description": "a path like /v<release>/install.sh",
		"type":        "object",
	})
	require.NoError(t, err)

	text := string(encoded)

	assert.Contains(t, text, "/v<release>/install.sh",
		"HTML escaping would write this as \\u003crelease\\u003e in a document people read")
	assert.Contains(t, text, "\n  \"description\"", "two-space indentation")
	assert.True(t, strings.HasSuffix(text, "\n"), "the committed file ends in a newline")
}

func keys(properties map[string]any) []string {
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}

	return names
}
