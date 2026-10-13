package rules

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Methods pivot will forward, and the reason there is a fixed list.
//
// pivot is a read-only perimeter guard: no customer will ever have write
// access through it, which is the premise the whole rules model rests on.
// A fixed method set is how that becomes a property of the code
// rather than a property of whichever rule set happens to be loaded. PUT,
// PATCH and DELETE are refused before the rules are consulted and no rule can
// name them, so a misconfigured allow list cannot grant a write.
//
// POST is in the set because a read is not always a GET: the Shopware search
// API, and plenty of others, take their query in a POST body. It is in the set
// of *forwardable* methods, not of permitted ones - deny-by-default still
// means a POST reaches the backend only through an explicit allow rule.
var ForwardableMethods = []string{"GET", "HEAD", "POST"}

// WriteMethods are refused structurally. Listed so an error can name them.
var WriteMethods = []string{"PUT", "PATCH", "DELETE", "CONNECT", "TRACE"}

// Wildcard is the method token meaning "every forwardable method".
const Wildcard = "*"

// MaxRules bounds one rule document, so a malformed file cannot be turned into
// an unbounded compile.
const MaxRules = 512

// Kind identifies how a rule's pattern is matched.
type Kind string

// The pattern kinds. Each entry declares its own, so nothing is guessed from
// the shape of the pattern string.
const (
	KindGlob  Kind = "glob"
	KindRegex Kind = "regex"
)

// Scope records where a rule came from, for the audit record and for
// `rules test`.
type Scope string

// The rule scopes.
const (
	// ScopeGlobal is the instance-wide rule set.
	ScopeGlobal Scope = "global"

	// ScopeClient is one client's additions.
	ScopeClient Scope = "client"
)

// Rule is one entry of an allow or deny list.
type Rule struct {
	// Methods is the method set. "*" means every forwardable method, and is
	// accepted on a deny rule only - see Validate.
	Methods []string `json:"methods" yaml:"methods"`

	// Glob and Regex are the pattern; exactly one must be set.
	Glob  string `json:"glob,omitempty"  yaml:"glob,omitempty"`
	Regex string `json:"regex,omitempty" yaml:"regex,omitempty"`

	// Comment is an optional note. It is shown by `rules list` and recorded
	// in the audit entry of a request this rule decided, which is what makes
	// "why is this denied" answerable without reading the rule file.
	Comment string `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// Cache is a route's caching configuration.
type Cache struct {
	// TTL is how long a response may be cached. Zero means not cacheable.
	TTL time.Duration `json:"ttl" yaml:"ttl"`

	// Encrypt seals the cached body with a key derived from the service
	// secret. Off by default, and the default is the
	// unsafe direction for anything touching personal data - pivot cannot
	// work out from a path whether a response carries it.
	Encrypt bool `json:"encrypt,omitempty" yaml:"encrypt,omitempty"`

	// Shared drops the client scope from the cache key, so one cached entry
	// serves every client. Only correct when the response cannot differ
	// between clients, which pivot cannot verify - two clients with different
	// backend permissions can get different responses from one path.
	Shared bool `json:"shared,omitempty" yaml:"shared,omitempty"`
}

// Route is a cacheable path pattern.
type Route struct {
	Methods []string `json:"methods,omitempty" yaml:"methods,omitempty"`
	Glob    string   `json:"glob,omitempty"    yaml:"glob,omitempty"`
	Regex   string   `json:"regex,omitempty"   yaml:"regex,omitempty"`
	Cache   Cache    `json:"cache"             yaml:"cache"`
}

// RuleLists are a document's deny and allow lists.
//
// A named type rather than an anonymous struct inside Document, so the
// generated schema can describe it as a definition of its own and reflection
// can reach it by type rather than by field position.
type RuleLists struct {
	// Deny is evaluated first and wins. A deny rule may use the method
	// wildcard; an allow rule may not.
	Deny []Rule `json:"deny,omitempty"  yaml:"deny,omitempty"`

	// Allow is what opens a path, since nothing is permitted by default.
	Allow []Rule `json:"allow,omitempty" yaml:"allow,omitempty"`
}

// Document is the on-disk and in-Valkey shape of a rule set.
type Document struct {
	// Rules are the deny and allow lists.
	Rules RuleLists `json:"rules" yaml:"rules"`

	// Routes configure caching per path.
	Routes []Route `json:"routes,omitempty" yaml:"routes,omitempty"`
}

// Validation errors.
var (
	errNoPattern             = errors.New("rules: a rule needs a glob or a regex")
	errBothPatterns          = errors.New("rules: a rule may not have both a glob and a regex")
	errNoMethods             = errors.New("rules: a rule needs at least one method")
	errGlobNotAbsolute       = errors.New("rules: a glob must begin with /")
	errGlobBackslash         = errors.New("rules: a glob may not contain a backslash")
	errGlobDoubleStarSegment = errors.New(
		"rules: ** must be a whole segment, as in /api/**, not part of one")
	errGlobTripleStar    = errors.New("rules: *** has no meaning; use ** to cross segments")
	errGlobTrailingSlash = errors.New(
		"rules: a pattern may not end in /, because a normalized path never does")

	// ErrWriteMethod is returned for a rule naming a method pivot will never
	// forward.
	ErrWriteMethod = errors.New("rules: pivot never forwards write methods")

	// ErrWildcardAllow is returned for an allow rule with a wildcard method.
	ErrWildcardAllow = errors.New("rules: an allow rule must name its methods explicitly")

	// ErrTooManyRules is returned for a document over MaxRules.
	ErrTooManyRules = errors.New("rules: too many rules")
)

// compiled is one rule ready to match.
type compiled struct {
	rule    Rule
	scope   Scope
	kind    Kind
	methods map[string]bool
	any     bool
	regex   *regexp.Regexp
}

// matches reports whether a method and normalized path match this rule.
func (c *compiled) matches(method, path string) bool {
	if !c.any && !c.methods[method] {
		return false
	}

	if c.kind == KindRegex {
		return c.regex.MatchString(path)
	}

	return matchGlob(c.rule.Glob, path)
}

// describe renders the rule for an audit entry or `rules test`.
func (c *compiled) describe() string {
	pattern := c.rule.Glob
	if c.kind == KindRegex {
		pattern = c.rule.Regex
	}

	methods := Wildcard
	if !c.any {
		methods = strings.Join(sortedMethods(c.methods), ",")
	}

	out := fmt.Sprintf("%s %s:%s %s", c.scope, c.kind, pattern, methods)
	if c.rule.Comment != "" {
		out += " (" + c.rule.Comment + ")"
	}

	return out
}

// sortedMethods returns a method set in a stable order, so two runs of
// `rules list` produce identical output.
func sortedMethods(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for method := range set {
		out = append(out, method)
	}

	sort.Strings(out)

	return out
}

// Set is a compiled rule set, ready to evaluate requests.
//
// Immutable once built. A reload replaces the whole value behind an atomic
// pointer rather than mutating one in place, for the same reason signpost's
// route table is swapped whole: a request must never see a rule set that is
// half-updated, because the half it saw might be the half without the deny.
type Set struct {
	deny   []*compiled
	allow  []*compiled
	routes []*compiledRoute
	scope  Scope
}

// compiledRoute is one cacheable route.
type compiledRoute struct {
	route   Route
	kind    Kind
	methods map[string]bool
	any     bool
	regex   *regexp.Regexp
}

// matches reports whether a method and path match this route.
func (c *compiledRoute) matches(method, path string) bool {
	if !c.any && !c.methods[method] {
		return false
	}

	if c.kind == KindRegex {
		return c.regex.MatchString(path)
	}

	return matchGlob(c.route.Glob, path)
}

// Compile validates a document and returns a matchable rule set.
//
// Compiling and validating are the same operation on purpose: a rule set that
// compiled but had not been validated would be one an operator could load and
// only discover was wrong when a request hit it. `rules validate` runs exactly
// this, without a server.
func Compile(doc Document, scope Scope) (*Set, error) {
	total := len(doc.Rules.Deny) + len(doc.Rules.Allow) + len(doc.Routes)
	if total > MaxRules {
		return nil, fmt.Errorf("%w: %d entries, the limit is %d", ErrTooManyRules, total, MaxRules)
	}

	set := &Set{scope: scope}

	for i, rule := range doc.Rules.Deny {
		entry, err := compileRule(rule, scope, true)
		if err != nil {
			return nil, fmt.Errorf("deny rule %d: %w", i, err)
		}

		set.deny = append(set.deny, entry)
	}

	for i, rule := range doc.Rules.Allow {
		entry, err := compileRule(rule, scope, false)
		if err != nil {
			return nil, fmt.Errorf("allow rule %d: %w", i, err)
		}

		set.allow = append(set.allow, entry)
	}

	for i, route := range doc.Routes {
		entry, err := compileRoute(route)
		if err != nil {
			return nil, fmt.Errorf("route %d: %w", i, err)
		}

		set.routes = append(set.routes, entry)
	}

	return set, nil
}

// compileRule validates and compiles one rule.
func compileRule(rule Rule, scope Scope, isDeny bool) (*compiled, error) {
	entry := &compiled{rule: rule, scope: scope}

	switch {
	case rule.Glob != "" && rule.Regex != "":
		return nil, errBothPatterns
	case rule.Glob != "":
		entry.kind = KindGlob

		if err := validateGlob(rule.Glob); err != nil {
			return nil, err
		}
	case rule.Regex != "":
		entry.kind = KindRegex

		compiledRegex, err := compileRegex(rule.Regex)
		if err != nil {
			return nil, err
		}

		entry.regex = compiledRegex
	default:
		return nil, errNoPattern
	}

	methods, any, err := compileMethods(rule.Methods, isDeny)
	if err != nil {
		return nil, err
	}

	entry.methods, entry.any = methods, any

	return entry, nil
}

// compileRoute validates and compiles one cacheable route.
func compileRoute(route Route) (*compiledRoute, error) {
	entry := &compiledRoute{route: route}

	switch {
	case route.Glob != "" && route.Regex != "":
		return nil, errBothPatterns
	case route.Glob != "":
		entry.kind = KindGlob

		if err := validateGlob(route.Glob); err != nil {
			return nil, err
		}
	case route.Regex != "":
		entry.kind = KindRegex

		compiledRegex, err := compileRegex(route.Regex)
		if err != nil {
			return nil, err
		}

		entry.regex = compiledRegex
	default:
		return nil, errNoPattern
	}

	if route.Cache.TTL < 0 {
		return nil, fmt.Errorf("cache ttl must not be negative, got %s", route.Cache.TTL)
	}

	// A route with no methods is cacheable for every forwardable method,
	// which is the sensible default for a cache entry: the key covers the
	// method, so a GET and a POST to one path are different entries anyway.
	if len(route.Methods) == 0 {
		entry.any = true

		return entry, nil
	}

	methods, any, err := compileMethods(route.Methods, true)
	if err != nil {
		return nil, err
	}

	entry.methods, entry.any = methods, any

	return entry, nil
}

// compileRegex anchors and compiles a pattern.
//
// Anchored automatically: an unanchored pattern matches a
// substring, so "/api/product" would match "/api/product/../../admin" before
// normalization and "/evil/api/product" after. Anchoring is not a convenience
// here, it is the difference between a rule that means what it says and one
// that does not.
//
// RE2 rather than backtracking, which is stdlib regexp's guarantee: matching
// is linear in the input, so a configured pattern cannot be made to hang on a
// path an attacker chooses.
func compileRegex(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, errNoPattern
	}

	anchored := pattern

	if !strings.HasPrefix(anchored, "^") {
		anchored = "^" + anchored
	}

	if !strings.HasSuffix(anchored, "$") {
		anchored += "$"
	}

	compiled, err := regexp.Compile(anchored)
	if err != nil {
		return nil, fmt.Errorf("regex %q does not compile: %w", pattern, err)
	}

	return compiled, nil
}

// compileMethods validates a method set.
//
// A wildcard is accepted on a deny rule and refused on an allow rule, which is
// asymmetric on purpose. "Deny every method on this path" is a complete
// statement an author can mean. "Allow every method on this path" in a
// deny-by-default security configuration is almost always a shorthand nobody
// re-reads, so pivot makes the author name GET or POST and the rule say what
// it grants.
func compileMethods(methods []string, allowWildcard bool) (map[string]bool, bool, error) {
	if len(methods) == 0 {
		return nil, false, errNoMethods
	}

	set := make(map[string]bool, len(methods))

	for _, raw := range methods {
		method := strings.ToUpper(strings.TrimSpace(raw))

		if method == Wildcard {
			if !allowWildcard {
				return nil, false, ErrWildcardAllow
			}

			return nil, true, nil
		}

		if isWriteMethod(method) {
			return nil, false, fmt.Errorf(
				"%w: %s is a write method, and pivot forwards only %s",
				ErrWriteMethod, method, strings.Join(ForwardableMethods, ", "))
		}

		if !isForwardable(method) {
			return nil, false, fmt.Errorf(
				"%w: %q is not a method pivot forwards, which are %s",
				ErrWriteMethod, method, strings.Join(ForwardableMethods, ", "))
		}

		set[method] = true
	}

	return set, false, nil
}

// isForwardable reports whether pivot will ever forward a method.
func isForwardable(method string) bool {
	for _, allowed := range ForwardableMethods {
		if method == allowed {
			return true
		}
	}

	return false
}

// isWriteMethod reports whether a method is one of the refused writes.
func isWriteMethod(method string) bool {
	for _, write := range WriteMethods {
		if method == write {
			return true
		}
	}

	return false
}

// IsForwardable reports whether pivot will forward a method at all.
//
// Consulted by the pipeline before the rules, so a write is refused whatever
// the loaded rule set says. That ordering is what makes "pivot never forwards a
// write" a property of the code: there is no rule set, global or per-client, that can
// put a PUT through.
func IsForwardable(method string) bool { return isForwardable(strings.ToUpper(method)) }
