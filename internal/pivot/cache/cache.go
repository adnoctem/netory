// Package cache is pivot's response cache (§7.2) and its optional per-route
// encryption (§7.3).
//
// # What is cached, and what is never cached
//
// Only a route an operator explicitly marked cacheable, for the TTL that route
// declares. That is the opposite of an HTTP cache's defaults and deliberately
// so: pivot sits in front of an API whose responses are mostly
// customer-specific, and a cache that guessed would be a cross-customer data
// leak rather than a performance regression.
//
// The key always covers the client, so two customers cannot share an entry.
// §7.2 allows a route to be marked shared, which drops the client from the
// key, and that flag is the one setting in this package that can leak data
// between customers if it is wrong - two clients with different backend
// permissions can get different responses from one path. It is an operator
// judgement pivot cannot make for them.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// InfoCacheEncryption is the HKDF label the per-route sealing key is derived
// under, as §8.1 names it.
const InfoCacheEncryption = "pivot/cache-encryption"

// MaxBodyBytes bounds a cacheable response body.
//
// A response larger than this is served through and not stored. The cache is
// shared state in Valkey, which is memory on a server pivot does not own, so
// an unbounded entry size would let one large response evict every other
// customer's entries.
const MaxBodyBytes = 8 << 20 // 8 MiB

// Entry is a cached response.
type Entry struct {
	// Status is the HTTP status code.
	Status int

	// Header is the subset of response headers worth replaying. See
	// cacheableHeaders for why it is a subset.
	Header http.Header

	// Body is the response body.
	Body []byte

	// StoredAt is when the entry was written, used for the Age header so a
	// client can tell a cached response from a fresh one.
	StoredAt time.Time
}

// Age returns how long the entry has been cached.
func (e Entry) Age(now time.Time) time.Duration {
	if e.StoredAt.IsZero() {
		return 0
	}

	age := now.Sub(e.StoredAt)
	if age < 0 {
		// A replica whose clock is behind the one that wrote the entry. Zero
		// rather than a negative Age, which is not a thing HTTP can express.
		return 0
	}

	return age
}

// cacheableHeaders are the response headers pivot replays from a cached entry.
//
// An allowlist, not a denylist. A cached response is replayed to a different
// request than the one that produced it, so a header carrying anything
// request-specific or credential-bearing must not come along - Set-Cookie
// above all, which would hand one customer's session to another. Listing what
// is safe means a header the backend invents later is dropped rather than
// replayed by default.
var cacheableHeaders = []string{
	"Content-Type",
	"Content-Language",
	"Content-Encoding",
	"ETag",
	"Last-Modified",
	"Vary",
	"Link",
}

// FilterHeaders returns the subset of a response's headers worth caching.
func FilterHeaders(header http.Header) http.Header {
	out := make(http.Header, len(cacheableHeaders))

	for _, name := range cacheableHeaders {
		if values := header.Values(name); len(values) > 0 {
			for _, value := range values {
				out.Add(name, value)
			}
		}
	}

	return out
}

// Storable reports whether a backend response may be cached, and why not when
// it may not.
//
// §7.2 requires Cache-Control: no-store and private to be honoured. They are
// the backend telling pivot that this response is not shareable, and a proxy
// that ignored that would be caching whatever the backend was careful about.
func Storable(status int, header http.Header, bodyLen int) (bool, string) {
	if status != http.StatusOK {
		// Only 200 is cached. A 404 or a 403 is cheap to produce and caching
		// one would make a transient backend state stick, while a 5xx must
		// never be replayed as though it were an answer.
		return false, "status is not 200"
	}

	for _, directive := range cacheControlDirectives(header) {
		switch directive {
		case "no-store", "private", "no-cache":
			return false, "the backend sent Cache-Control: " + directive
		}
	}

	// A response that sets a cookie is per-session by construction.
	if len(header.Values("Set-Cookie")) > 0 {
		return false, "the response sets a cookie"
	}

	if bodyLen > MaxBodyBytes {
		return false, "the body is larger than " + strconv.Itoa(MaxBodyBytes) + " bytes"
	}

	// A Vary the cache cannot honour means the response depends on a request
	// header pivot's key does not cover, so replaying it could answer the
	// wrong variant. Vary: Accept-Encoding is the exception, because pivot
	// forwards and stores the encoded body as one unit.
	for _, field := range varyFields(header) {
		if field == "*" {
			return false, "the response varies on *"
		}

		if field != "accept-encoding" {
			return false, "the response varies on " + field + ", which the cache key does not cover"
		}
	}

	return true, ""
}

// cacheControlDirectives returns a response's Cache-Control directives,
// lowercased and without their arguments.
func cacheControlDirectives(header http.Header) []string {
	var out []string

	for _, value := range header.Values("Cache-Control") {
		for part := range strings.SplitSeq(value, ",") {
			directive, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if directive != "" {
				out = append(out, strings.ToLower(directive))
			}
		}
	}

	return out
}

// varyFields returns a response's Vary fields, lowercased.
func varyFields(header http.Header) []string {
	var out []string

	for _, value := range header.Values("Vary") {
		for part := range strings.SplitSeq(value, ",") {
			if field := strings.ToLower(strings.TrimSpace(part)); field != "" {
				out = append(out, field)
			}
		}
	}

	return out
}

// Key identifies a cached response.
type Key struct {
	// Client is the pivot client the entry belongs to, empty for a shared
	// route.
	Client string

	// Method, Path, Query and BodyHash are the request the entry answers.
	Method   string
	Path     string
	Query    string
	BodyHash string
}

// MaxKeyedBodyBytes bounds the request body the cache key covers.
//
// A search POST body is small. A request larger than this is not cached at
// all rather than keyed on a truncated body, which would make two different
// requests share an entry - the one failure mode a cache must never have.
const MaxKeyedBodyBytes = 1 << 20 // 1 MiB

// ErrBodyTooLarge is returned when a request body is too large to key on.
var ErrBodyTooLarge = errors.New("cache: the request body is too large to cache on")

// NewKey builds a cache key for a request.
//
// The body is hashed rather than included, because the key becomes a Valkey
// key and a search body can be kilobytes. The query is canonicalized so that
// two orderings of the same parameters hit one entry: "?limit=1&page=2" and
// "?page=2&limit=1" are the same request to any backend, and treating them as
// two would halve the hit rate for no benefit.
//
// scoped is false only for a route explicitly marked shared.
func NewKey(client, method, normalizedPath, rawQuery string, body []byte, scoped bool) (Key, error) {
	if len(body) > MaxKeyedBodyBytes {
		return Key{}, ErrBodyTooLarge
	}

	key := Key{
		Method:   strings.ToUpper(method),
		Path:     normalizedPath,
		Query:    canonicalQuery(rawQuery),
		BodyHash: hashBody(body),
	}

	if scoped {
		key.Client = client
	}

	return key, nil
}

// String renders the key for storage.
//
// Hashed into one short, fixed-length string rather than concatenated, for two
// reasons. A path can be 4 KiB and kv.ValidateKey bounds a key at 1 KiB, so a
// concatenated key would be rejected for long but legitimate requests. And a
// key built from attacker-influenced strings would otherwise carry them into
// the keyspace, where a crafted path could collide with the prefix of another
// entry's key.
//
// The components are joined with a byte that cannot appear in any of them, so
// no two different keys can produce one string by shifting a boundary.
func (k Key) String() string {
	var b strings.Builder

	// A newline is the separator: it cannot appear in a method, a normalized
	// path, a canonical query or a hex hash, and it cannot appear in a client
	// id either.
	b.WriteString(k.Client)
	b.WriteByte('\n')
	b.WriteString(k.Method)
	b.WriteByte('\n')
	b.WriteString(k.Path)
	b.WriteByte('\n')
	b.WriteString(k.Query)
	b.WriteByte('\n')
	b.WriteString(k.BodyHash)

	sum := sha256.Sum256([]byte(b.String()))

	return hex.EncodeToString(sum[:])
}

// Scoped reports whether the key covers a client.
func (k Key) Scoped() bool { return k.Client != "" }

// canonicalQuery sorts a query string's parameters.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}

	values, err := url.ParseQuery(raw)
	if err != nil {
		// An unparsable query is keyed verbatim rather than dropped. Two
		// requests with the same malformed query share an entry, which is
		// correct; what must not happen is two different malformed queries
		// sharing one.
		return raw
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	var b strings.Builder

	for _, key := range keys {
		entries := values[key]
		// Repeated parameters keep their order: for some APIs "?id=a&id=b" is
		// a list, and sorting it would make two different requests equal.
		for _, value := range entries {
			if b.Len() > 0 {
				b.WriteByte('&')
			}

			b.WriteString(url.QueryEscape(key))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(value))
		}
	}

	return b.String()
}

// hashBody returns the hex SHA-256 of a request body, or the empty string for
// no body.
func hashBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	sum := sha256.Sum256(body)

	return hex.EncodeToString(sum[:])
}
