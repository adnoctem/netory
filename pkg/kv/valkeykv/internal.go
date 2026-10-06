package valkeykv

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/valkey-io/valkey-go"

	"github.com/adnoctem/netory/pkg/kv"
)

// physical builds the Valkey key for a namespace and key.
func physical(ns, key string) string {
	var b strings.Builder

	b.Grow(len(ns) + 1 + len(key))
	b.WriteString(ns)
	b.WriteByte(separator)
	b.WriteString(key)

	return b.String()
}

// namespacePrefix is the physical prefix every key in a namespace shares.
func namespacePrefix(ns string) string { return ns + string(separator) }

// precheck runs the guards every operation shares: a closed store, a cancelled
// context, and namespace and key validation.
//
// Context cancellation is checked here as well as being passed to valkey-go,
// which honours it on the wire. Checking first means a cancelled caller does
// not occupy a pooled connection to be told what it already knew.
func (s *Store) precheck(ctx context.Context, ns, key string) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return kv.Validate(ns, key)
}

// precheckPrefix is precheck for the operations taking a Keys or Scan prefix,
// where an empty prefix is legal.
func (s *Store) precheckPrefix(ctx context.Context, ns, prefix string) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return kv.ValidatePrefixed(ns, prefix)
}

// scanKeys walks a namespace with SCAN, calling fn with each namespace-relative
// key.
//
// SCAN rather than KEYS, which is the difference between a command that yields
// in bounded steps and one that blocks the server for the length of the whole
// keyspace. The cost is that SCAN guarantees no ordering and may return a key
// more than once across a resharding - which is exactly why kv.Store documents
// Keys and Scan as unordered, and why they belong on administrative paths
// rather than on a request.
func (s *Store) scanKeys(ctx context.Context, ns, prefix string, fn func(string) error) error {
	match := scanPattern(ns, prefix)
	seen := make(map[string]struct{})

	var cursor uint64

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		entry, err := s.client.Do(ctx, s.client.B().Scan().
			Cursor(cursor).
			Match(match).
			Count(s.scanCount).
			Build()).AsScanEntry()
		if err != nil {
			return s.translate(err, "scan", ns, prefix)
		}

		for _, physicalKey := range entry.Elements {
			relative, ok := strings.CutPrefix(physicalKey, namespacePrefix(ns))
			if !ok {
				// A key matched the pattern without carrying the namespace
				// prefix, which the pattern makes impossible - but a glob is
				// not a parser, so this is checked rather than assumed.
				continue
			}

			// SCAN may yield the same key twice in one iteration; a caller
			// seeing one entry twice would double-count an outbox drain.
			if _, duplicate := seen[relative]; duplicate {
				continue
			}

			seen[relative] = struct{}{}

			if err := fn(relative); err != nil {
				if errors.Is(err, kv.ErrStopIteration) {
					return nil
				}

				return err
			}
		}

		cursor = entry.Cursor
		if cursor == 0 {
			return nil
		}
	}
}

// scanPattern builds the MATCH glob for a namespace and prefix.
//
// The namespace and the prefix are escaped, because MATCH takes a glob and a
// key may legitimately contain its metacharacters: kv.ValidateKey allows
// anything but NUL, so a key like "rule[1]" is valid and would otherwise be
// read as a character class. An unescaped '*' in a prefix would be worse -
// it would silently widen the scan.
func scanPattern(ns, prefix string) string {
	var b strings.Builder

	b.WriteString(escapeGlob(namespacePrefix(ns)))
	b.WriteString(escapeGlob(prefix))
	b.WriteByte('*')

	return b.String()
}

// escapeGlob backslash-escapes the characters Valkey's pattern matcher treats
// as special.
func escapeGlob(value string) string {
	var b strings.Builder

	b.Grow(len(value))

	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case '*', '?', '[', ']', '^', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}

	return b.String()
}

// casScript is the compare-and-swap.
//
// It returns 0 for an absent key rather than creating one: kv.Store specifies
// that an absent key is (false, nil) and never an implicit create, so that
// CompareAndSwap and SetIfAbsent stay non-overlapping primitives.
//
// The comparison is a plain Lua string equality on bytes. Not constant-time,
// matching badgerkv - the values here are opaque state and nothing about a CAS
// outcome is a secret. Comparing a token is a different concern and belongs in
// the service.
var casScript = valkey.NewLuaScript(`
local current = redis.call('GET', KEYS[1])
if current == false then
  return 0
end
if current ~= ARGV[1] then
  return 0
end
if ARGV[3] == '1' then
  redis.call('SET', KEYS[1], ARGV[2], 'PXAT', ARGV[4])
else
  redis.call('SET', KEYS[1], ARGV[2])
end
return 1
`)

// incrementScript is INCRBY with its expiry applied in the same execution.
//
// PERSIST on the no-TTL path, which looks redundant and is not: badgerkv
// writes an entry with no expiry, so an increment with no TTL option leaves a
// permanent key whatever the key held before. Without PERSIST, a counter that
// had been created with a TTL would keep it here and not there, and the two
// backends would disagree about when a counter disappears.
var incrementScript = valkey.NewLuaScript(`
local next = redis.call('INCRBY', KEYS[1], ARGV[1])
if ARGV[2] == '1' then
  redis.call('PEXPIREAT', KEYS[1], ARGV[3])
else
  redis.call('PERSIST', KEYS[1])
end
return next
`)

// notAnInteger matches the error Valkey returns both for a non-numeric value
// and for an increment that would overflow a 64-bit counter.
//
// Matched on its text because that is what the protocol gives: Valkey sends
// errors as strings, and valkey-go surfaces them as such. The two cases are
// deliberately not separated - kv.ErrNotAnInteger covers both, since from a
// caller's point of view "this is not a counter I can add to" is the same
// answer either way.
const notAnIntegerMessage = "not an integer or out of range"

// overflowMessage is what Valkey answers when INCRBY would exceed int64.
const overflowMessage = "increment or decrement would overflow"

// translate maps a valkey-go error onto this package's contract.
//
// Every error gains the operation, the namespace and the key, because the
// alternative is a log line saying a Valkey command failed without saying
// which key it was for - and with one store holding every replica's state,
// that is the only detail that makes the message actionable.
func (s *Store) translate(err error, op, ns, key string) error {
	if err == nil {
		return nil
	}

	// A store closed underneath an in-flight call reports as closed rather
	// than as a transport failure, which is what a caller racing Close with a
	// last write would otherwise see.
	if s.closed.Load() {
		return kv.ErrClosed
	}

	if isNotAnInteger(err) {
		return fmt.Errorf("%w: %s %s/%s: %w", kv.ErrNotAnInteger, op, ns, key, err)
	}

	return fmt.Errorf("valkeykv: %s %s/%s: %w", op, ns, key, err)
}

// isNotAnInteger reports whether err is Valkey's non-numeric or overflow
// complaint.
func isNotAnInteger(err error) bool {
	var valkeyErr *valkey.ValkeyError
	if !errors.As(err, &valkeyErr) {
		return false
	}

	message := valkeyErr.Error()

	return strings.Contains(message, notAnIntegerMessage) ||
		strings.Contains(message, overflowMessage)
}
