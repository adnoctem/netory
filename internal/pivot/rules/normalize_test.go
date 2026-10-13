package rules_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/rules"
)

func TestNormalize(t *testing.T) {
	t.Parallel()

	asrt := assert.New(t)

	for input, want := range map[string]string{
		// Already canonical.
		"/api/product": "/api/product",
		"/":            "/",

		// Repeated slashes collapse.
		"//api//product": "/api/product",
		"/api///product": "/api/product",
		"/////":          "/",

		// Dot segments resolve.
		"/api/./product":           "/api/product",
		"/api/v1/../product":       "/api/product",
		"/api/v1/v2/../../product": "/api/product",
		"/api/product/.":           "/api/product",

		// An escape of an unreserved character is equivalent to the character,
		// so decoding it makes two spellings of one path compare equal.
		"/api/pro%64uct": "/api/product",
		"/api/%7Etilde":  "/api/~tilde",
		"/api/a%2Db":     "/api/a-b",

		// A reserved character stays encoded, because decoding it would change
		// what the path means - but the hex is uppercased so %3f and %3F are
		// one path.
		"/api/a%3fb": "/api/a%3Fb",
		"/api/a%3Fb": "/api/a%3Fb",
		"/api/a%20b": "/api/a%20b",

		// A trailing slash is dropped, so one route has exactly one spelling
		// before any rule sees it. See resolveSegments for the trade.
		"/api//":         "/api",
		"/api/search/":   "/api/search",
		"/api/search///": "/api/search",
	} {
		got, err := rules.Normalize(input)
		asrt.NoError(err, "input %q", input)
		asrt.Equal(want, got, "input %q", input)
	}
}

// Every one of these is a request pivot refuses rather than guesses at. An
// ambiguous path is the precise thing normalization exists to eliminate: pivot and the
// backend's router must see the same request, and a path with two readings has
// no single answer to forward.
func TestNormalizeRejects(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		path string
		want error
	}{
		"not absolute": {
			path: "api/product",
			want: rules.ErrPathNotAbsolute,
		},
		"empty": {
			path: "",
			want: rules.ErrPathNotAbsolute,
		},
		"scheme-relative": {
			path: "//evil.example/api",
			want: nil, // collapses to /evil.example/api, which is a path, not an authority
		},
		"literal null byte": {
			path: "/api/pro\x00duct",
			want: rules.ErrPathNullByte,
		},
		"literal backslash": {
			path: `/api\product`,
			want: rules.ErrPathBackslash,
		},
		"encoded slash": {
			path: "/api/a%2Fb",
			want: rules.ErrPathEncodedSeparator,
		},
		"encoded slash lowercase": {
			path: "/api/a%2fb",
			want: rules.ErrPathEncodedSeparator,
		},
		"encoded backslash": {
			path: "/api/a%5Cb",
			want: rules.ErrPathEncodedSeparator,
		},
		"encoded null": {
			path: "/api/a%00b",
			want: rules.ErrPathEncodedSeparator,
		},
		"truncated escape": {
			path: "/api/a%2",
			want: rules.ErrPathBadEncoding,
		},
		"non-hex escape": {
			path: "/api/a%zzb",
			want: rules.ErrPathBadEncoding,
		},
		"climbs above root": {
			path: "/api/../../etc/passwd",
			want: rules.ErrPathEscapesRoot,
		},
		"climbs immediately": {
			path: "/../etc/passwd",
			want: rules.ErrPathEscapesRoot,
		},
		"too long": {
			path: "/" + strings.Repeat("a", rules.MaxPathLen),
			want: rules.ErrPathTooLong,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := rules.Normalize(test.path)

			if test.want == nil {
				require.NoError(t, err)
				assert.Equal(t, "/evil.example/api", got,
					"a scheme-relative-looking path is just a path once the slashes collapse")

				return
			}

			assert.ErrorIs(t, err, test.want)
		})
	}
}

// The attack this normalization exists to stop: a path that pivot's rules
// judge one way and a backend router reads another. Each of these would
// bypass a deny on /api/_action if it were matched before normalization, or if
// an encoded separator were decoded after matching.
func TestNormalizeClosesTheDoubleInterpretationGap(t *testing.T) {
	t.Parallel()

	denied, err := rules.Compile(mustParse(t, `
rules:
  deny:
    - { methods: ["*"], glob: "/api/_action/**" }
  allow:
    - { methods: [GET], glob: "/api/**" }
`), rules.ScopeGlobal)
	require.NoError(t, err)

	// Every spelling that resolves to the denied prefix must be denied, and
	// every spelling that cannot be resolved must be refused outright.
	for _, path := range []string{
		"/api/_action/order/state",
		"/api//_action/order/state",
		"/api/./_action/order/state",
		"/api/v1/../_action/order/state",
		"/api/_acti%6Fn/order/state",
	} {
		normalized, err := rules.Normalize(path)
		require.NoError(t, err, path)

		decision := denied.Evaluate("GET", normalized)
		assert.Equal(t, rules.OutcomeDenied, decision.Outcome,
			"%q normalized to %q and must still be denied", path, normalized)
	}

	// And the encoded-separator spellings never get as far as a rule.
	for _, path := range []string{
		"/api%2F_action/order/state",
		"/api/_action%2Forder",
	} {
		_, err := rules.Normalize(path)
		assert.ErrorIs(t, err, rules.ErrPathEncodedSeparator, path)
	}
}

func mustParse(t *testing.T, document string) rules.Document {
	t.Helper()

	doc, err := rules.Parse([]byte(document))
	require.NoError(t, err)

	return doc
}
