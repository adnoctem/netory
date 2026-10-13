package rules

import "strings"

// matchGlob reports whether a path matches a glob pattern.
//
// The syntax: `*` matches within one segment, `**` across
// segments, `?` matches one character within a segment. The whole path must
// match - there is no partial match, because a rule that matched a prefix of
// the path would allow everything underneath it by accident.
//
// Stdlib path.Match has no `**`, which is why this exists. Rather than
// backtracking over the raw strings, the match runs over segments with a
// dynamic-programming table: `**` can consume any number of segments, and a
// naive recursive matcher over a pattern with several of them degrades
// exponentially on input an attacker chooses. A table is O(pattern x path) and
// cannot be made to blow up.
func matchGlob(pattern, path string) bool {
	patternSegments := splitSegments(pattern)
	pathSegments := splitSegments(path)

	// reachable[j] reports whether the first i pattern segments can consume
	// the first j path segments. The row is rebuilt for each i.
	reachable := make([]bool, len(pathSegments)+1)
	reachable[0] = true

	for _, patternSegment := range patternSegments {
		next := make([]bool, len(pathSegments)+1)

		if patternSegment == "**" {
			// `**` consumes zero or more segments, so every position at or
			// after a reachable one stays reachable.
			carry := false

			for j := range next {
				if reachable[j] {
					carry = true
				}

				next[j] = carry
			}
		} else {
			for j := range pathSegments {
				if reachable[j] && matchSegment(patternSegment, pathSegments[j]) {
					next[j+1] = true
				}
			}
		}

		reachable = next
	}

	return reachable[len(pathSegments)]
}

// splitSegments splits a path or pattern into its non-empty segments.
//
// Empty segments are dropped so that a pattern written with a stray double
// slash still means what its author intended; normalized paths have none by
// construction.
func splitSegments(value string) []string {
	segments := make([]string, 0, 8)

	for segment := range strings.SplitSeq(value, "/") {
		if segment != "" {
			segments = append(segments, segment)
		}
	}

	return segments
}

// matchSegment matches one pattern segment against one path segment, with `*`
// and `?` but no separator crossing.
//
// Iterative with a single backtrack point rather than recursive: one `*` per
// segment is the common case, and the greedy-with-backtrack form is linear in
// practice and bounded in the worst case. Nothing here can cross a `/`,
// because neither string contains one.
func matchSegment(pattern, segment string) bool {
	var (
		p, s         int
		starP, starS = -1, 0
	)

	for s < len(segment) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			// Remember where to resume if the greedy choice fails.
			starP, starS = p, s
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == segment[s]):
			p++
			s++
		case starP >= 0:
			// Backtrack: let the remembered `*` absorb one more character.
			starS++
			p, s = starP+1, starS
		default:
			return false
		}
	}

	// Trailing `*`s match the empty remainder.
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}

	return p == len(pattern)
}

// validateGlob reports whether a glob pattern is usable.
//
// `***` and a `**` sharing a segment with other characters are refused rather
// than given a meaning. Both are things an author writes expecting one
// behaviour, and inventing one would make the pattern mean something the
// person who reviews the rule set does not expect.
func validateGlob(pattern string) error {
	if pattern == "" {
		return errNoPattern
	}

	if !strings.HasPrefix(pattern, "/") {
		return errGlobNotAbsolute
	}

	if strings.Contains(pattern, "\\") {
		return errGlobBackslash
	}

	// A normalized path never ends in a slash, so a pattern that does could
	// never match anything. Refused rather than silently dead: an operator who
	// writes a deny rule that matches nothing has a rule set that does not say
	// what they think it says.
	if len(pattern) > 1 && strings.HasSuffix(pattern, "/") {
		return errGlobTrailingSlash
	}

	for segment := range strings.SplitSeq(pattern, "/") {
		if !strings.Contains(segment, "**") {
			continue
		}

		if segment != "**" {
			return errGlobDoubleStarSegment
		}
	}

	if strings.Contains(pattern, "***") {
		return errGlobTripleStar
	}

	return nil
}
