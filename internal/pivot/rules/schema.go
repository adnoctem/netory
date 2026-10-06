package rules

import (
	"maps"
	"reflect"
	"strconv"
	"strings"

	"github.com/adnoctem/netory/pkg/schema"
)

// SchemaName is the committed schema's file name under docs/schema.
const SchemaName = "pivot-rules-v1.json"

// SchemaID is the rule document schema's identifier.
//
// Versioned independently of pivot's releases, because it describes a document
// format rather than a build: a tool pinned to v1 keeps working when pivot
// ships a v2 document. The base it is built from lives in pkg/schema, so
// moving where the schemas are served is one edit rather than one per service.
var SchemaID = schema.ID(SchemaName)

// SchemaDialect is the JSON Schema dialect the generated document declares.
const SchemaDialect = schema.Dialect

// Schema returns the rule document's JSON Schema, generated from the Go types.
//
// Generated rather than written, for the reason signpost's manifest schema is:
// Compile is what actually decides whether a document is usable, so a schema
// maintained beside it would be a second description of the same thing, free
// to drift the moment someone adds a field. Deriving it means the property
// names, their types and which ones are required come from the structs
// themselves, and the method set, the bounds and the glob rules come from the
// same constants validateGlob and compileMethods use. The committed document
// under docs/schema is this function's output, and a test fails if the two
// differ.
//
// What the schema deliberately does not express: whether a regex compiles as
// RE2, that the document's total entry count is within MaxRules (JSON Schema
// cannot add two array lengths), and the accumulative precedence between a
// global and a per-client set. A document that satisfies this schema is
// well-formed, not necessarily one pivot will accept - which is why
// `pivot rules validate` runs the real compiler and the schema is for editors
// and CI.
func Schema() ([]byte, error) {
	document := map[string]any{
		"$schema":     SchemaDialect,
		"$id":         SchemaID,
		"title":       "pivot rule document",
		"description": schemaDescription,
		"$defs": map[string]any{
			"denyRule":  ruleDefinition(true),
			"allowRule": ruleDefinition(false),
			"rules":     schema.Object(reflect.TypeFor[RuleLists](), ruleListConstraints),
			"route":     routeDefinition(),
			"cache":     schema.Object(reflect.TypeFor[Cache](), cacheConstraints),
		},
	}

	maps.Copy(document, schema.Object(reflect.TypeFor[Document](), documentConstraints))

	return schema.Encode(document)
}

// schemaDescription is the prose at the top of the generated document.
const schemaDescription = "A pivot rule document, as `pivot rules apply` takes it in YAML or JSON. " +
	"Nothing is permitted by default: a path reaches the backend only through an explicit allow " +
	"rule, and the deny list is evaluated first and wins. Satisfying this schema means the " +
	"document is well-formed; `pivot rules validate` runs the compiler that decides whether it is " +
	"usable, including whether every regex compiles and whether the whole document is within the " +
	"entry limit."

// documentConstraints describes Document's fields.
var documentConstraints = map[string]schema.Property{
	"rules": {
		Description: "The deny and allow lists. Required, and required to be meaningful: a " +
			"document with no allow list denies everything, which is a valid rule set and the " +
			"state a fresh pivot starts in.",
		Constraints: map[string]any{"$ref": "#/$defs/rules"},
	},
	"routes": {
		Description: "Per-path caching. A path with no route here is forwarded and never cached. " +
			"Routes are not a second allow list - a route does not permit anything the rules do " +
			"not.",
		Constraints: map[string]any{
			"type":     "array",
			"maxItems": MaxRules,
			"items":    map[string]any{"$ref": "#/$defs/route"},
		},
	},
}

// ruleListConstraints describes RuleLists' fields.
var ruleListConstraints = map[string]schema.Property{
	"deny": {
		Description: "Rules that refuse a request. Evaluated before the allow list and final - " +
			"a per-client document cannot reopen a path the global deny list refuses. These may " +
			"use the " + strconv.Quote(Wildcard) + " method wildcard.",
		Constraints: map[string]any{
			"type":     "array",
			"maxItems": MaxRules,
			"items":    map[string]any{"$ref": "#/$defs/denyRule"},
		},
	},
	"allow": {
		Description: "Rules that permit a request. Nothing is permitted without one. These must " +
			"name their methods explicitly; the wildcard is refused here, because an allow rule " +
			"is the one place where being broader than intended is unsafe.",
		Constraints: map[string]any{
			"type":     "array",
			"maxItems": MaxRules,
			"items":    map[string]any{"$ref": "#/$defs/allowRule"},
		},
	},
}

// cacheConstraints describes Cache's fields.
var cacheConstraints = map[string]schema.Property{
	"ttl": {
		Description: "How long a response may be cached; zero means not cacheable. In YAML this " +
			"is a Go duration string such as 30s, 1m or 1h. In JSON it is an integer count of " +
			"nanoseconds, because that is how Go encodes a duration - a JSON document with " +
			`"ttl": "1m" is rejected by the decoder, which is why both forms appear here.`,
		Constraints: map[string]any{
			"oneOf": []any{
				map[string]any{
					"type":        "string",
					"pattern":     `^[0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h)([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))*$`,
					"description": "A Go duration string, as written in YAML.",
				},
				map[string]any{
					"type":        "integer",
					"minimum":     0,
					"description": "Nanoseconds, as written in JSON.",
				},
			},
		},
	},
	"encrypt": {
		Description: "Seals the cached body with a key derived from PIVOT_SECRET. Off by " +
			"default, and the default is the unsafe direction for anything touching personal " +
			"data: pivot cannot work out from a path whether a response carries any, so this is " +
			"a judgement the operator makes per route.",
		Constraints: map[string]any{
			"type":    "boolean",
			"default": false,
		},
	},
	"shared": {
		Description: "Drops the client scope from the cache key, so one cached entry serves " +
			"every client. Only correct when the response cannot differ between clients, which " +
			"pivot cannot verify - two clients whose backend credentials carry different " +
			"permissions can get different responses from one path.",
		Constraints: map[string]any{
			"type":    "boolean",
			"default": false,
		},
	},
}

// ruleConstraints describes Rule's fields. The method constraint differs
// between a deny and an allow rule, so it is supplied by ruleDefinition.
func ruleConstraints(allowWildcard bool) map[string]schema.Property {
	methods := "The methods this rule covers. pivot forwards " +
		strings.Join(ForwardableMethods, ", ") + " and nothing else, whatever a rule says; " +
		"POST is in that set because a read is not always a GET - plenty of search APIs take " +
		"their query in a body. Case is not significant."

	if allowWildcard {
		methods += " " + strconv.Quote(Wildcard) + " means every forwardable method."
	}

	return map[string]schema.Property{
		"methods": {
			Description: methods,
			Constraints: map[string]any{
				"type":     "array",
				"minItems": 1,
				"items": map[string]any{
					"type":    "string",
					"pattern": methodPattern(allowWildcard),
				},
			},
		},
		"glob": {
			Description: "A path pattern. Must begin with '/', may not contain a backslash, may " +
				"not end in '/' - a normalized path never does, so such a pattern could never " +
				"match - and '**' must be a whole segment, as in /api/**. Exactly one of glob " +
				"or regex is required.",
			Constraints: map[string]any{
				"type":      "string",
				"minLength": 1,
				"pattern":   `^/([^/\\]*(/[^/\\]*)*)?$`,
				"not": map[string]any{
					"anyOf": []any{
						// ".+/" rather than "/", because a bare "/" is the one
						// pattern that may end in a slash: validateGlob
						// refuses a trailing slash only on a longer pattern,
						// since "/" is the root path rather than a directory.
						map[string]any{"pattern": `.+/$`},
						map[string]any{"pattern": `\*\*\*`},
						map[string]any{"pattern": `[^/]\*\*|\*\*[^/]`},
					},
				},
			},
		},
		"regex": {
			Description: "A path pattern as an RE2 expression, anchored at both ends by pivot " +
				"rather than by you. Whether it compiles is checked by " +
				"`pivot rules validate`, not here. Exactly one of glob or regex is required.",
			Constraints: map[string]any{
				"type":      "string",
				"minLength": 1,
			},
		},
		"comment": {
			Description: "An optional note. Shown by `pivot rules list` and recorded in the " +
				"audit entry of every request this rule decided, which is what makes \"why was " +
				"this denied\" answerable without reading the rule file. Every deny in the " +
				"documented examples carries one.",
			Constraints: map[string]any{"type": "string"},
		},
	}
}

// ruleDefinition builds the schema for a deny or an allow rule.
func ruleDefinition(allowWildcard bool) map[string]any {
	definition := schema.Object(reflect.TypeFor[Rule](), ruleConstraints(allowWildcard))
	definition["oneOf"] = patternChoice()

	return definition
}

// routeDefinition builds the schema for a cacheable route.
func routeDefinition() map[string]any {
	definition := schema.Object(reflect.TypeFor[Route](), ruleConstraints(false))

	// Route carries Rule's pattern fields and its own cache block, so the
	// pattern constraints are shared and only the cache is described here.
	properties, _ := definition["properties"].(map[string]any)
	properties["cache"] = map[string]any{
		"$ref": "#/$defs/cache",
		"description": "The caching configuration for paths this route matches. Required: a " +
			"route exists to configure caching, so one without a cache block says nothing.",
	}

	definition["oneOf"] = patternChoice()

	return definition
}

// patternChoice requires exactly one of glob and regex.
//
// Expressed here rather than left to the compiler, because it is the mistake
// an editor can catch while the file is being written: a rule with neither
// pattern matches nothing and a rule with both is ambiguous about which was
// meant.
func patternChoice() []any {
	return []any{
		map[string]any{
			"required": []any{"glob"},
			"not":      map[string]any{"required": []any{"regex"}},
		},
		map[string]any{
			"required": []any{"regex"},
			"not":      map[string]any{"required": []any{"glob"}},
		},
	}
}

// methodPattern builds a case-insensitive alternation over the forwardable
// methods.
//
// A pattern rather than an enum, because compileMethods upper-cases what it
// reads, so `get` is as valid as `GET` and an enum of upper-case tokens would
// mark a working document as wrong. ECMA-262 regular expressions, which is
// what JSON Schema specifies, have no inline case-insensitivity flag - hence
// the character classes. It is generated from ForwardableMethods, so the
// method set has exactly one definition.
func methodPattern(allowWildcard bool) string {
	alternatives := make([]string, 0, len(ForwardableMethods)+1)

	for _, method := range ForwardableMethods {
		var builder strings.Builder

		for _, letter := range method {
			builder.WriteByte('[')
			builder.WriteRune(letter)
			builder.WriteRune(letter + ('a' - 'A'))
			builder.WriteByte(']')
		}

		alternatives = append(alternatives, builder.String())
	}

	if allowWildcard {
		alternatives = append(alternatives, `\*`)
	}

	return "^(" + strings.Join(alternatives, "|") + ")$"
}
