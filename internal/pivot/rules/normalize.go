// Package rules is pivot's path rule engine: normalization, matching, and the
// accumulation of a global rule set with per-client additions.
//
// # Why normalization lives here
//
// §2 states the property the whole layer rests on: pivot canonicalizes a path
// before matching and forwards the canonical form, so pivot and the backend's
// router always see the same request. A rule is only as strong as the path it
// matched, and any difference between the path pivot judged and the path the
// backend routed is a second interpretation for an attacker to aim at.
// Normalizing in the same package as the matcher is how those two stay one
// decision rather than two that happen to agree.
package rules

import (
	"errors"
	"fmt"
	"strings"
)

// MaxPathLen bounds a request path.
//
// Generous for an API path and bounded so that normalization, which allocates
// proportionally to its input, cannot be made expensive by a long one.
const MaxPathLen = 4096

// Sentinel errors from normalization. Each one maps to a 400: an ambiguous
// request is refused rather than guessed at.
var (
	// ErrPathTooLong is returned for a path over MaxPathLen.
	ErrPathTooLong = errors.New("rules: path is too long")

	// ErrPathNotAbsolute is returned for a path that does not begin with "/".
	ErrPathNotAbsolute = errors.New("rules: path must begin with /")

	// ErrPathEncodedSeparator is returned for an encoded "/", "\" or NUL.
	//
	// These are refused rather than decoded, which is the whole point. A
	// percent-encoded slash that pivot decoded would change the path's segment
	// structure after the rules matched it; one that pivot passed through
	// unchanged might still be decoded by the backend's router. Neither is
	// acceptable, so the request does not proceed.
	ErrPathEncodedSeparator = errors.New("rules: path contains an encoded separator or null byte")

	// ErrPathBadEncoding is returned for a malformed percent-escape.
	ErrPathBadEncoding = errors.New("rules: path contains a malformed percent-escape")

	// ErrPathEscapesRoot is returned for a path whose ".." segments climb
	// above the root.
	ErrPathEscapesRoot = errors.New("rules: path climbs above the root")

	// ErrPathNullByte is returned for a literal NUL in the path.
	ErrPathNullByte = errors.New("rules: path contains a null byte")

	// ErrPathBackslash is returned for a literal backslash.
	//
	// Refused because some routers and some filesystems treat it as a
	// separator and pivot does not, which is exactly the kind of disagreement
	// §2 exists to remove.
	ErrPathBackslash = errors.New("rules: path contains a backslash")
)

// Normalize canonicalizes a request path for matching and forwarding.
//
// The order is deliberate: reject what must never be decoded, then decode what
// is safe, then resolve the segment structure. Decoding before rejecting would
// mean an encoded "/" had already become a separator by the time it was
// checked.
func Normalize(raw string) (string, error) {
	if len(raw) > MaxPathLen {
		return "", fmt.Errorf("%w: %d bytes, the limit is %d", ErrPathTooLong, len(raw), MaxPathLen)
	}

	if !strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("%w: got %q", ErrPathNotAbsolute, raw)
	}

	if strings.IndexByte(raw, 0x00) >= 0 {
		return "", ErrPathNullByte
	}

	if strings.IndexByte(raw, '\\') >= 0 {
		return "", ErrPathBackslash
	}

	decoded, err := decodeUnreserved(raw)
	if err != nil {
		return "", err
	}

	return resolveSegments(decoded)
}

// decodeUnreserved percent-decodes only the unreserved characters and
// uppercases the hex of every escape it leaves in place.
//
// Decoding only the unreserved set is RFC 3986 §6.2.2.2 canonicalization: an
// escape of an unreserved character is equivalent to the character, so
// decoding it loses nothing and makes two spellings of one path compare equal.
// Everything else stays encoded, because decoding a reserved character would
// change what the path means.
func decodeUnreserved(raw string) (string, error) {
	// No escapes is the common case and needs no allocation.
	if strings.IndexByte(raw, '%') < 0 {
		return raw, nil
	}

	var b strings.Builder

	b.Grow(len(raw))

	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c != '%' {
			b.WriteByte(c)

			continue
		}

		if i+2 >= len(raw) {
			return "", fmt.Errorf("%w: %q ends mid-escape", ErrPathBadEncoding, raw)
		}

		hi, ok := unhex(raw[i+1])
		if !ok {
			return "", fmt.Errorf("%w: %%%s", ErrPathBadEncoding, raw[i+1:i+3])
		}

		lo, ok := unhex(raw[i+2])
		if !ok {
			return "", fmt.Errorf("%w: %%%s", ErrPathBadEncoding, raw[i+1:i+3])
		}

		value := hi<<4 | lo

		switch value {
		case '/', '\\', 0x00:
			return "", fmt.Errorf("%w: %%%02X", ErrPathEncodedSeparator, value)
		}

		if isUnreserved(value) {
			b.WriteByte(value)
		} else {
			// Left encoded, with the hex uppercased so that %2f and %2F are
			// one path rather than two.
			b.WriteByte('%')
			b.WriteByte(upperHex[value>>4])
			b.WriteByte(upperHex[value&0x0f])
		}

		i += 2
	}

	return b.String(), nil
}

// upperHex is the digit set for re-encoding an escape.
const upperHex = "0123456789ABCDEF"

// unhex decodes one hex digit.
func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// isUnreserved reports whether a byte is RFC 3986 unreserved.
func isUnreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z',
		c >= 'A' && c <= 'Z',
		c >= '0' && c <= '9',
		c == '-', c == '.', c == '_', c == '~':
		return true
	default:
		return false
	}
}

// resolveSegments collapses repeated slashes, resolves "." and "..", and
// drops a trailing slash.
//
// Written here rather than taken from path.Clean, which absorbs a ".." that
// climbs above the root where pivot must refuse the request outright.
//
// Dropping the trailing slash is a normalization step §5.1 does not list, and
// it is there because the alternative is worse. Keeping it would leave two
// spellings of one route - "/api/product" and "/api/product/" - which is the
// ambiguity §2 exists to remove, and the matcher would then have to decide
// whether a rule for one covers the other. Either answer is a trap: covering
// it widens every allow rule by a path its author did not write, and not
// covering it answers 403 to a client whose URL differs by one character for
// reasons nothing in the response explains.
//
// Collapsing instead gives exactly one string per route, before any rule sees
// it, and the forwarded path is still the matched path - so §2 holds. The
// trade is a backend that genuinely routes "/x" and "/x/" to different
// handlers, which pivot cannot then distinguish; that is rare, it fails
// towards the canonical form rather than towards more access, and the
// normalized path is in the audit record so the cause is visible.
func resolveSegments(path string) (string, error) {
	segments := make([]string, 0, 8)

	for segment := range strings.SplitSeq(path, "/") {
		switch segment {
		case "", ".":
			// An empty segment is a repeated or trailing slash; "." is a
			// no-op. Both are dropped.
		case "..":
			if len(segments) == 0 {
				return "", fmt.Errorf("%w: %q", ErrPathEscapesRoot, path)
			}

			segments = segments[:len(segments)-1]
		default:
			segments = append(segments, segment)
		}
	}

	if len(segments) == 0 {
		return "/", nil
	}

	var b strings.Builder

	b.Grow(len(path))

	for _, segment := range segments {
		b.WriteByte('/')
		b.WriteString(segment)
	}

	return b.String(), nil
}
