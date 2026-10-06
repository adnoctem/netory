// Package schema generates JSON Schema documents from Go types.
//
// Two services take a document a user writes by hand - signpost's bundle
// manifest and pivot's rule set - and both want the same thing from a schema:
// an editor that offers the right keys and marks a wrong one, and a CI job
// that can reject a malformed file before it reaches a server. Both also want
// the schema to be *generated*, because a schema maintained beside the structs
// that validate the document is a second description of the same thing, free
// to drift the moment someone adds a field.
//
// What a generated schema cannot express stays in Go. Reserved paths, cross-field
// uniqueness, that a referenced file is present in an archive, that exactly one
// of two fields is set - none of those are expressible here, and a document
// satisfying one of these schemas is well-formed rather than valid. Each
// service's own validation remains the thing that decides.
package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"sort"
	"strings"
)

// Dialect is the JSON Schema dialect the generated documents declare.
const Dialect = "https://json-schema.org/draft/2020-12/schema"

// BaseURL is the prefix every schema's $id is built from.
//
// One constant for both services, because moving where the schemas are served
// should be one edit rather than one per service. That move is expected: the
// intent is for signpost to serve them, which it is built to do - it already
// serves immutable, checksummed files at configured paths - rather than
// depending on a third party to host the identity of netory's own documents.
//
// An $id does not have to resolve for a schema to work; an editor pointed at a
// local file validates against it either way. It has to be stable, which is
// why it is versioned by the document version rather than by a release.
const BaseURL = "https://adnoctem.github.io/netory/schema"

// ID returns the $id for a schema document.
func ID(name string) string { return BaseURL + "/" + name }

// Property describes one field's constraints.
//
// The constraints that cannot be read off a Go type - a maximum length, a
// pattern, a default, an enum - are declared next to the field they belong to
// and sourced from the same constants the validator uses. Each service's
// schema test asserts that every exported field has an entry, so a field added
// without a description fails the build rather than silently appearing as an
// unconstrained string.
type Property struct {
	// Description is the field's prose.
	Description string

	// Constraints are merged into the generated property.
	Constraints map[string]any
}

// Object builds an object schema from a struct type and its properties.
//
// Required is derived from the json tag's omitempty, so there is no second
// list to keep in step: a field the encoder may omit is a field the schema
// must not require.
//
// Unknown fields are rejected, because both services' parsers reject them. A
// typo in a key must fail rather than be ignored, and it should fail the same
// way in an editor as it does on the server.
func Object(typ reflect.Type, properties map[string]Property) map[string]any {
	generated := map[string]any{}

	var required []string

	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		name, optional, ok := jsonName(field)
		if !ok {
			continue
		}

		property := map[string]any{}

		if described, found := properties[name]; found {
			maps.Copy(property, described.Constraints)

			if described.Description != "" {
				property["description"] = described.Description
			}
		}

		// Falls back to the Go type when no constraint declared one, so a
		// field with a forgotten entry still gets a correct type rather than
		// no type at all. The per-service test is what stops that shipping.
		//
		// Not when the property already says what it accepts in another way.
		// A `oneOf` over a string and an integer with `"type": "integer"`
		// added beside it rejects the string, because both apply - which is
		// how a time.Duration written as "5m" came to be refused by a schema
		// that was meant to allow it.
		if _, hasType := property["type"]; !hasType && !constrainsType(property) {
			property["type"] = JSONType(field.Type)
		}

		generated[name] = property

		if !optional {
			required = append(required, name)
		}
	}

	sort.Strings(required)

	object := map[string]any{
		"type":                 "object",
		"properties":           generated,
		"additionalProperties": false,
	}

	// Omitted rather than emitted empty. A nil slice encodes as null, and
	// "required": null is not a valid schema - some validators reject the
	// whole document over it. An object all of whose fields are optional has
	// no required list, which is what leaving the key out says.
	if len(required) > 0 {
		object["required"] = required
	}

	return object
}

// typeKeywords are the keywords that say what a property accepts without
// naming a type, and so make a derived `type` redundant at best and wrong at
// worst.
var typeKeywords = []string{"$ref", "oneOf", "anyOf", "allOf", "const", "enum"}

// constrainsType reports whether a property already constrains its own type.
func constrainsType(property map[string]any) bool {
	for _, keyword := range typeKeywords {
		if _, found := property[keyword]; found {
			return true
		}
	}

	return false
}

// Fields returns the JSON property names of a struct's exported fields, which
// is what a test compares against the declared properties.
func Fields(typ reflect.Type) []string {
	var names []string

	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		if name, _, ok := jsonName(field); ok {
			names = append(names, name)
		}
	}

	sort.Strings(names)

	return names
}

// Encode renders a schema document as the bytes committed under docs/schema.
//
// Two decisions about the output, both so the committed file is readable: two-
// space indentation, and HTML escaping off. The default encoder would write a
// description containing "<release>" as "<release>", which is
// correct JSON and unreadable in a document people are meant to read.
func Encode(document map[string]any) ([]byte, error) {
	var buffer bytes.Buffer

	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(document); err != nil {
		return nil, fmt.Errorf("schema: encode the document: %w", err)
	}

	return buffer.Bytes(), nil
}

// jsonName returns a field's JSON property name and whether it is optional.
func jsonName(field reflect.StructField) (name string, optional, ok bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false, false
	}

	name, options, _ := strings.Cut(tag, ",")
	if name == "" {
		name = field.Name
	}

	return name, strings.Contains(options, "omitempty"), true
}

// JSONType maps a Go type onto a JSON Schema type.
func JSONType(typ reflect.Type) string {
	switch typ.Kind() {
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice, reflect.Array:
		return "array"
	case reflect.Map, reflect.Struct:
		return "object"
	default:
		return "string"
	}
}
