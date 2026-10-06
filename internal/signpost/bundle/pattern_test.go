package bundle_test

import "regexp"

// compilePattern compiles a JSON Schema pattern with Go's regexp engine.
//
// JSON Schema specifies ECMA-262 regular expressions and Go's RE2 is not quite
// that, which is fine for the patterns this schema uses: they are character
// classes and anchors, the subset where the two agree. Isolated in one
// function so that a pattern needing more than that subset fails here rather
// than silently meaning something different to an editor than it does to this
// test.
func compilePattern(pattern string) (*regexp.Regexp, error) { return regexp.Compile(pattern) }
