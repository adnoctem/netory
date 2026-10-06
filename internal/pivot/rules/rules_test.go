package rules_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/pivot/rules"
)

func TestGlobMatching(t *testing.T) {
	t.Parallel()

	asrt := assert.New(t)

	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// `*` stays within one segment.
		{"/api/*", "/api/product", true},
		{"/api/*", "/api/product/id", false},
		{"/api/search/*", "/api/search/product", true},
		{"/api/search/*", "/api/search/product/extra", false},

		// `**` crosses segments, including none.
		{"/api/**", "/api", true},
		{"/api/**", "/api/product", true},
		{"/api/**", "/api/a/b/c/d", true},
		{"/api/_action/**", "/api/_action", true},
		{"/api/_action/**", "/api/_action/order/state", true},
		{"/api/_action/**", "/api/product", false},

		// A `**` in the middle.
		{"/api/**/state", "/api/order/state", true},
		{"/api/**/state", "/api/a/b/c/state", true},
		{"/api/**/state", "/api/state", true},
		{"/api/**/state", "/api/order/other", false},

		// Partial segments.
		{"/api/search/customer*", "/api/search/customer", true},
		{"/api/search/customer*", "/api/search/customer-group", true},
		{"/api/search/customer*", "/api/search/order", false},
		{"/api/pro?uct", "/api/product", true},
		{"/api/pro?uct", "/api/prooduct", false},

		// Anchored at both ends: a pattern must match the whole path, or a
		// rule for /api/product would cover /api/product-secret.
		{"/api/product", "/api/product", true},
		{"/api/product", "/api/product/id", false},
		{"/api/product", "/evil/api/product", false},

		// Several wildcards in one segment.
		{"/api/*-*", "/api/a-b", true},
		{"/api/*-*", "/api/a-b-c", true},
		{"/api/*x*", "/api/axb", true},
		{"/api/*x*", "/api/ab", false},

		// A normalized path never carries a trailing slash, so this case
		// cannot arise through the pipeline - asserted here to pin that a raw
		// trailing slash is not treated as a distinct segment.
		{"/api/product", "/api/product", true},
	}

	for _, test := range cases {
		set, err := rules.Compile(mustParse(t, "rules:\n  allow:\n    - { methods: [GET], glob: \""+
			test.pattern+"\" }\n"), rules.ScopeGlobal)
		require.NoError(t, err, test.pattern)

		got := set.Evaluate("GET", test.path).Allowed()
		asrt.Equal(test.want, got, "pattern %q against %q", test.pattern, test.path)
	}
}

// A naive recursive `**` matcher degrades exponentially on a pattern with
// several of them. The table-based matcher does not, and this is the input
// that would show the difference - it must finish immediately rather than
// hang.
func TestGlobDoesNotBlowUp(t *testing.T) {
	t.Parallel()

	pattern := "/" + strings.Repeat("**/", 40) + "nomatch"
	path := "/" + strings.Repeat("a/", 200) + "end"

	set, err := rules.Compile(mustParse(t,
		"rules:\n  allow:\n    - { methods: [GET], glob: \""+pattern+"\" }\n"), rules.ScopeGlobal)
	require.NoError(t, err)

	done := make(chan bool, 1)

	go func() { done <- set.Evaluate("GET", path).Allowed() }()

	select {
	case allowed := <-done:
		assert.False(t, allowed)
	case <-time.After(5 * time.Second):
		t.Fatal("matching a pathological pattern took longer than 5s")
	}
}

func TestGlobValidation(t *testing.T) {
	t.Parallel()

	for name, pattern := range map[string]string{
		"not absolute":       "api/**",
		"backslash":          "/api\\\\product",
		"partial doublestar": "/api/x**",
		"triple star":        "/api/***",
		"trailing slash":     "/api/product/",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := rules.Compile(mustParse(t,
				"rules:\n  allow:\n    - { methods: [GET], glob: \""+pattern+"\" }\n"),
				rules.ScopeGlobal)
			assert.Error(t, err)
		})
	}
}

// A regex rule is anchored whether or not its author anchored it. Unanchored,
// "/api/product" would match "/evil/api/product" and a deny rule would be
// trivially sidestepped.
func TestRegexIsAnchored(t *testing.T) {
	t.Parallel()

	set, err := rules.Compile(mustParse(t, `
rules:
  allow:
    - { methods: [GET], regex: "/api/[a-z]+" }
`), rules.ScopeGlobal)
	require.NoError(t, err)

	asrt := assert.New(t)
	asrt.True(set.Evaluate("GET", "/api/product").Allowed())
	asrt.False(set.Evaluate("GET", "/evil/api/product").Allowed(),
		"an unanchored pattern would have matched this")
	asrt.False(set.Evaluate("GET", "/api/product/extra").Allowed())
}

// §10.1: no customer will ever have write access, so the method set is fixed
// in code and no rule set can widen it.
func TestWriteMethodsAreRefusedStructurally(t *testing.T) {
	t.Parallel()

	t.Run("a rule naming a write method does not compile", func(t *testing.T) {
		t.Parallel()

		for _, method := range []string{"PUT", "PATCH", "DELETE", "CONNECT", "TRACE"} {
			_, err := rules.Compile(mustParse(t,
				"rules:\n  allow:\n    - { methods: ["+method+"], glob: \"/api/**\" }\n"),
				rules.ScopeGlobal)
			assert.ErrorIs(t, err, rules.ErrWriteMethod, method)
		}
	})

	t.Run("a write is refused even by a wildcard deny-everything allow", func(t *testing.T) {
		t.Parallel()

		// The most permissive rule set that will compile.
		set, err := rules.Compile(mustParse(t, `
rules:
  allow:
    - { methods: [GET, HEAD, POST], glob: "/**" }
`), rules.ScopeGlobal)
		require.NoError(t, err)

		for _, method := range []string{"PUT", "PATCH", "DELETE", "OPTIONS"} {
			decision := set.Evaluate(method, "/api/product")
			assert.Equal(t, rules.OutcomeMethodRefused, decision.Outcome, method)
			assert.False(t, decision.Allowed(), method)
		}

		// And the three forwardable ones go through.
		for _, method := range []string{"GET", "HEAD", "POST"} {
			assert.True(t, set.Evaluate(method, "/api/product").Allowed(), method)
		}
	})

	t.Run("IsForwardable is the pipeline's gate", func(t *testing.T) {
		t.Parallel()

		asrt := assert.New(t)
		asrt.True(rules.IsForwardable("GET"))
		asrt.True(rules.IsForwardable("get"), "the check is case-insensitive")
		asrt.True(rules.IsForwardable("POST"))
		asrt.False(rules.IsForwardable("PUT"))
		asrt.False(rules.IsForwardable("DELETE"))
		asrt.False(rules.IsForwardable("OPTIONS"))
	})
}

// A wildcard method is accepted on a deny rule and refused on an allow rule.
// "Deny everything on this path" is a complete statement; "allow everything"
// in a deny-by-default configuration is a shorthand nobody re-reads.
func TestWildcardMethodIsDenyOnly(t *testing.T) {
	t.Parallel()

	_, err := rules.Compile(mustParse(t, `
rules:
  deny:
    - { methods: ["*"], glob: "/api/_action/**" }
`), rules.ScopeGlobal)
	require.NoError(t, err, "a wildcard deny is a complete statement")

	_, err = rules.Compile(mustParse(t, `
rules:
  allow:
    - { methods: ["*"], glob: "/api/**" }
`), rules.ScopeGlobal)
	assert.ErrorIs(t, err, rules.ErrWildcardAllow)
}

func TestDenyBeatsAllow(t *testing.T) {
	t.Parallel()

	// The allow rule is written first and is broader, so order in the file
	// cannot be what decides.
	set, err := rules.Compile(mustParse(t, `
rules:
  allow:
    - { methods: [GET], glob: "/api/**" }
  deny:
    - { methods: ["*"], glob: "/api/_action/**" }
`), rules.ScopeGlobal)
	require.NoError(t, err)

	asrt := assert.New(t)

	denied := set.Evaluate("GET", "/api/_action/order")
	asrt.Equal(rules.OutcomeDenied, denied.Outcome)
	asrt.Contains(denied.Rule, "_action")

	allowed := set.Evaluate("GET", "/api/product")
	asrt.Equal(rules.OutcomeAllowed, allowed.Outcome)
}

func TestDenyByDefault(t *testing.T) {
	t.Parallel()

	set, err := rules.Compile(mustParse(t, `
rules:
  allow:
    - { methods: [GET], glob: "/api/product" }
`), rules.ScopeGlobal)
	require.NoError(t, err)

	decision := set.Evaluate("GET", "/api/order")
	assert.Equal(t, rules.OutcomeNoMatch, decision.Outcome,
		"a path matching nothing is denied, and the outcome says which kind of denial it was")
	assert.False(t, decision.Allowed())
	assert.Empty(t, decision.Rule, "no rule decided, so none is named")

	// An empty set permits nothing, which is what an unconfigured instance
	// enforces.
	assert.False(t, rules.EmptySet().Evaluate("GET", "/api/product").Allowed())
	assert.True(t, rules.EmptySet().Empty())
}

// §10.2's model: a client's rules add to the global ones and can never reopen
// a path the global set denies.
func TestMergeIsAccumulativeAndGlobalDenyWins(t *testing.T) {
	t.Parallel()

	global, err := rules.Compile(mustParse(t, `
rules:
  deny:
    - { methods: ["*"], glob: "/api/_action/**", comment: "global deny" }
  allow:
    - { methods: [GET], glob: "/api/product" }
`), rules.ScopeGlobal)
	require.NoError(t, err)

	client, err := rules.Compile(mustParse(t, `
rules:
  deny:
    - { methods: ["*"], glob: "/api/order", comment: "this client may not read orders" }
  allow:
    - { methods: [GET], glob: "/api/manufacturer" }
    - { methods: [GET], glob: "/api/_action/**" }
`), rules.ScopeClient)
	require.NoError(t, err)

	merged := rules.Merge(global, client)
	asrt := assert.New(t)

	// The client's extra allow is honoured.
	asrt.True(merged.Evaluate("GET", "/api/manufacturer").Allowed(),
		"a client rule may add a path the global set does not grant")

	// The global allow still applies.
	asrt.True(merged.Evaluate("GET", "/api/product").Allowed())

	// The client's own deny applies, and the audit record attributes it.
	order := merged.Evaluate("GET", "/api/order")
	asrt.Equal(rules.OutcomeDenied, order.Outcome)
	asrt.Equal(rules.ScopeClient, order.Scope)

	// And the client's attempt to allow a globally denied path does not work.
	action := merged.Evaluate("GET", "/api/_action/order/state")
	asrt.Equal(rules.OutcomeDenied, action.Outcome,
		"a client allow rule must never reopen a globally denied path")
	asrt.Equal(rules.ScopeGlobal, action.Scope,
		"the global rule is the one to name, since it is the one that cannot be changed per client")
	asrt.Contains(action.Rule, "global deny")
}

func TestMergeHandlesMissingSides(t *testing.T) {
	t.Parallel()

	global, err := rules.Compile(mustParse(t, `
rules:
  allow:
    - { methods: [GET], glob: "/api/product" }
`), rules.ScopeGlobal)
	require.NoError(t, err)

	asrt := assert.New(t)
	asrt.True(rules.Merge(global, nil).Evaluate("GET", "/api/product").Allowed())
	asrt.True(rules.Merge(nil, global).Evaluate("GET", "/api/product").Allowed())
	asrt.False(rules.Merge(nil, nil).Evaluate("GET", "/api/product").Allowed())
}

// Merging must not alias the global set's backing arrays into the merged one,
// or a later reload would mutate a rule set a request is already holding.
func TestMergeDoesNotAliasTheGlobalSet(t *testing.T) {
	t.Parallel()

	global, err := rules.Compile(mustParse(t, `
rules:
  deny:
    - { methods: ["*"], glob: "/api/a" }
  allow:
    - { methods: [GET], glob: "/api/product" }
`), rules.ScopeGlobal)
	require.NoError(t, err)

	client, err := rules.Compile(mustParse(t, `
rules:
  deny:
    - { methods: ["*"], glob: "/api/b" }
  allow:
    - { methods: [GET], glob: "/api/other" }
`), rules.ScopeClient)
	require.NoError(t, err)

	merged := rules.Merge(global, client)

	deny, allow, _ := merged.Counts()
	assert.Equal(t, 2, deny)
	assert.Equal(t, 2, allow)

	// The global set is unchanged by the merge.
	globalDeny, globalAllow, _ := global.Counts()
	assert.Equal(t, 1, globalDeny)
	assert.Equal(t, 1, globalAllow)
}

func TestCacheRoutes(t *testing.T) {
	t.Parallel()

	set, err := rules.Compile(mustParse(t, `
rules:
  allow:
    - { methods: [POST], glob: "/api/search/*" }
routes:
  - methods: [POST]
    glob: /api/search/product
    cache: { ttl: 5m }
  - methods: [POST]
    glob: /api/search/order
    cache: { ttl: 1m, encrypt: true }
`), rules.ScopeGlobal)
	require.NoError(t, err)

	asrt := assert.New(t)

	product, ok := set.CacheFor("POST", "/api/search/product")
	require.True(t, ok)
	asrt.Equal(5*time.Minute, product.TTL)
	asrt.False(product.Encrypt)

	order, ok := set.CacheFor("POST", "/api/search/order")
	require.True(t, ok)
	asrt.Equal(time.Minute, order.TTL)
	asrt.True(order.Encrypt)

	// A path no route covers is not cacheable, which is the default §7.2
	// specifies: only routes explicitly marked cacheable are cached.
	_, ok = set.CacheFor("POST", "/api/search/manufacturer")
	asrt.False(ok)
	asrt.Zero(set.CacheTTL("POST", "/api/search/manufacturer"))

	// A different method on a covered path is not covered either.
	_, ok = set.CacheFor("GET", "/api/search/product")
	asrt.False(ok)
}

// A client route overrides the global TTL for its path, which is a caching
// decision rather than an access-control one: the rules have already allowed
// the request by the time a route is consulted.
func TestClientRoutesTakePrecedence(t *testing.T) {
	t.Parallel()

	global, err := rules.Compile(mustParse(t, `
routes:
  - { glob: "/api/search/product", cache: { ttl: 5m } }
`), rules.ScopeGlobal)
	require.NoError(t, err)

	client, err := rules.Compile(mustParse(t, `
routes:
  - { glob: "/api/search/product", cache: { ttl: 30s } }
`), rules.ScopeClient)
	require.NoError(t, err)

	cache, ok := rules.Merge(global, client).CacheFor("GET", "/api/search/product")
	require.True(t, ok)
	assert.Equal(t, 30*time.Second, cache.TTL)
}

func TestParseRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	// The wrong key that matters most: a document whose allow list is named
	// anything but "allow" would load with no allow list, which denies
	// everything and presents as a broken service rather than a broken file.
	_, err := rules.Parse(
		[]byte("rules:\n  allow_list:\n    - { methods: [GET], glob: \"/api/**\" }\n"))
	assert.Error(t, err)

	_, err = rules.Parse([]byte(`{"rules":{"allow":[{"methods":["GET"],"glob":"/api/**","typo":1}]}}`))
	assert.Error(t, err)
}

func TestParseAcceptsJSONAndYAML(t *testing.T) {
	t.Parallel()

	yamlDoc, err := rules.Parse([]byte("rules:\n  allow:\n    - { methods: [GET], glob: \"/api/**\" }\n"))
	require.NoError(t, err)

	jsonDoc, err := rules.Parse([]byte(`{"rules":{"allow":[{"methods":["GET"],"glob":"/api/**"}]}}`))
	require.NoError(t, err)

	assert.Equal(t, yamlDoc, jsonDoc, "the two encodings must produce the same document")
}

func TestRoundTripThroughStorage(t *testing.T) {
	t.Parallel()

	doc := exampleDocument(t, "shopware-readonly.yaml")

	encoded, err := rules.EncodeJSON(doc)
	require.NoError(t, err)

	decoded, err := rules.Parse(encoded)
	require.NoError(t, err)

	assert.Equal(t, doc, decoded, "a document stored in Valkey and read back must be unchanged")
}

// examplesDir holds the rule documents the documentation tells operators to
// copy, relative to this package.
const examplesDir = "../../../docs/examples/pivot"

// Every example document must compile.
//
// pivot ships no rule set, so these files are what an operator starts from -
// and a documented example that does not compile is worse than none, because
// it is met as a validation error in bytes they did not write. The directory
// is walked rather than listed, so a new example is covered by writing it.
func TestExampleDocumentsCompile(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(examplesDir)
	require.NoError(t, err)

	var found int

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		found++

		t.Run(entry.Name(), func(t *testing.T) {
			t.Parallel()

			doc := exampleDocument(t, entry.Name())

			set, err := rules.Compile(doc, rules.ScopeGlobal)
			require.NoError(t, err)

			if entry.Name() == "deny-all.yaml" {
				assert.True(t, set.Empty(), "deny-all must permit nothing")

				return
			}

			assert.False(t, set.Empty(), "%s permits nothing, which no example should", entry.Name())
		})
	}

	assert.NotZero(t, found, "the examples directory is empty, so the documentation has nothing to offer")
}

// The Shopware example is the rule set an operator is most likely to apply
// without reading all of it, so its headline properties are asserted rather
// than assumed. It is also the document the end-to-end suite applies against a
// backend speaking the Admin API's shapes, which is what §10.6 rests on.
func TestShopwareExampleBehaviour(t *testing.T) {
	t.Parallel()

	set, err := rules.Compile(exampleDocument(t, "shopware-readonly.yaml"), rules.ScopeGlobal)
	require.NoError(t, err)

	asrt := assert.New(t)

	// Denied, with the CVE reasoning reachable from the decision.
	action := set.Evaluate("GET", "/api/_action/order/state")
	asrt.Equal(rules.OutcomeDenied, action.Outcome)
	asrt.Contains(action.Rule, "CVE-2026-48014")

	for _, path := range []string{
		"/api/oauth/token",
		"/api/search/customer",
		"/api/search-ids/customer-group",
		"/api/_info/routes",
	} {
		asrt.Equal(rules.OutcomeDenied, set.Evaluate("GET", path).Outcome, path)
		asrt.Equal(rules.OutcomeDenied, set.Evaluate("POST", path).Outcome, path)
	}

	// Allowed reads.
	asrt.True(set.Evaluate("GET", "/api/product").Allowed())
	asrt.True(set.Evaluate("GET", "/api/product/0123456789abcdef0123456789abcdef").Allowed())
	asrt.True(set.Evaluate("POST", "/api/search/product").Allowed())
	asrt.True(set.Evaluate("POST", "/api/search-ids/product").Allowed())

	// Not allowed: a POST to a plain entity path is a write in Shopware's API.
	asrt.False(set.Evaluate("POST", "/api/product").Allowed())

	// And no write method gets through regardless.
	for _, method := range []string{"PUT", "PATCH", "DELETE"} {
		asrt.Equal(rules.OutcomeMethodRefused, set.Evaluate(method, "/api/product").Outcome, method)
	}
}

// exampleDocument reads and parses one of the documented examples.
func exampleDocument(t *testing.T, name string) rules.Document {
	t.Helper()

	raw, err := os.ReadFile(filepath.Join(examplesDir, name))
	require.NoError(t, err, "the documented example is missing")

	doc, err := rules.Parse(raw)
	require.NoError(t, err, "%s does not parse", name)

	return doc
}

func TestTooManyRules(t *testing.T) {
	t.Parallel()

	var document strings.Builder

	document.WriteString("rules:\n  allow:\n")

	for range rules.MaxRules + 1 {
		document.WriteString("    - { methods: [GET], glob: \"/api/**\" }\n")
	}

	_, err := rules.Compile(mustParse(t, document.String()), rules.ScopeGlobal)
	assert.ErrorIs(t, err, rules.ErrTooManyRules)
}
