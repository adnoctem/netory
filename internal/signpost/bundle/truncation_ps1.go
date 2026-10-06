package bundle

import (
	"regexp"
	"strings"
)

// The PowerShell truncation check (§9.5).
//
// PowerShell parses a whole script before executing any of it, so a truncation
// that breaks syntax is caught by the interpreter. That is not enough on its
// own: a truncation can leave syntactically valid code, and
//
//	Remove-Item -Recurse C:\target
//	Install-Thing
//
// cut after the first line parses cleanly and is destructive. So the same
// wrapper discipline applies, and the structural requirement is the mirror of
// the shell one:
//
//	function Main {
//	    # install logic
//	}
//	Main @args
//
// Concretely, ignoring blank lines and comments, a .ps1 file passes when:
//
//  1. it defines at least one function;
//  2. its last top-level statement invokes a function defined in the file; and
//  3. every other top-level statement is a prelude directive that cannot act
//     on the system - a #Requires line, a param block, Set-StrictMode, a
//     preference-variable assignment, [CmdletBinding()], or a using statement.
//
// Anything else at the top level is treated as a command, which is the
// conservative direction.

// ps1FunctionDef matches a function or filter definition's opening line.
//
// PowerShell function names allow a wide character set, including hyphens for
// the Verb-Noun convention, so the pattern is correspondingly permissive about
// the name while remaining strict about the shape.
var ps1FunctionDef = regexp.MustCompile(
	`^\s*(?:function|filter)\s+([A-Za-z_][A-Za-z0-9_.\-]*)\s*(?:\(.*\))?\s*\{?\s*$`)

// ps1Prelude matches top-level statements that cannot act on the system.
var ps1Prelude = regexp.MustCompile(
	`^\s*(?:` +
		// #Requires directives. A comment to PowerShell's lexer, but load
		// bearing, and conventionally first.
		`#Requires\b` +
		// Strict mode and the error/progress preference variables, which is
		// how a well-written installer opens.
		`|Set-StrictMode\b` +
		`|\$(?:ErrorActionPreference|ProgressPreference|WarningPreference|InformationPreference|ConfirmPreference|VerbosePreference|DebugPreference)\s*=` +
		// Attributes and a param block belong to the script, not to a
		// statement.
		`|\[CmdletBinding\(` +
		`|\[OutputType\(` +
		`|param\s*\(` +
		// using namespace / using module are parse-time directives.
		`|using\s+(?:namespace|module)\s` +
		`)`)

// ps1Invocation matches a top-level call to a named function.
//
// `Main`, `Main @args`, `Main -Verbose` and `& Main` all count; anything that
// chains a second statement does not, for the same reason as in the shell
// check.
var ps1Invocation = regexp.MustCompile(`^\s*&?\s*([A-Za-z_][A-Za-z0-9_.\-]*)\s*(.*)$`)

// ps1AssignmentPreference reports a preference assignment whose value is a
// subexpression, which would execute.
var ps1Subexpression = regexp.MustCompile(`\$\(|@\(`)

// checkPowerShell applies the structural check to a PowerShell script.
func checkPowerShell(file string, content []byte) error {
	lines := strings.Split(normaliseNewlines(string(content)), "\n")

	defined := map[string]bool{}
	var topLevel []numberedLine

	var (
		depth        int
		parenDepth   int
		blockComment bool
	)

	for i, raw := range lines {
		number := i + 1
		line := raw

		// Block comments can span lines and may contain braces, so they are
		// consumed before anything else looks at the text.
		if blockComment {
			if index := strings.Index(line, "#>"); index >= 0 {
				blockComment = false
				line = line[index+2:]
			} else {
				continue
			}
		}

		stripped, opensBlockComment := stripPowerShellComment(line)
		if opensBlockComment {
			blockComment = true
		}

		trimmed := strings.TrimSpace(stripped)
		if trimmed == "" {
			continue
		}

		// A param block spans lines; its parentheses are tracked so its
		// contents are not mistaken for statements.
		if parenDepth > 0 {
			parenDepth += parenDelta(stripped)

			continue
		}

		if depth == 0 {
			if match := ps1FunctionDef.FindStringSubmatch(stripped); match != nil {
				defined[strings.ToLower(match[1])] = true
				depth += braceDelta(stripped)

				continue
			}

			if ps1Prelude.MatchString(stripped) {
				// A param block opens a parenthesised region to skip.
				if delta := parenDelta(stripped); delta > 0 {
					parenDepth += delta
				}

				if ps1Subexpression.MatchString(trimmed) {
					return &TruncationError{
						File: file, Line: number, Text: trimmed,
						Reason: "assigns from a subexpression, which executes at the top level",
					}
				}

				depth += braceDelta(stripped)

				continue
			}

			topLevel = append(topLevel, numberedLine{number: number, text: trimmed})
		}

		depth += braceDelta(stripped)
		if depth < 0 {
			return &TruncationError{
				File: file, Line: number, Text: trimmed,
				Reason: "unbalanced braces, so the script's structure cannot be checked",
			}
		}
	}

	if depth != 0 {
		return &TruncationError{
			File:   file,
			Reason: "unbalanced braces, so the script's structure cannot be checked",
		}
	}

	if len(defined) == 0 {
		return &TruncationError{
			File:   file,
			Reason: "no function definition found; wrap the logic in a function and call it on the last line",
		}
	}

	if len(topLevel) == 0 {
		return &TruncationError{
			File:   file,
			Reason: "the script defines functions but never calls one, so it would do nothing",
		}
	}

	last := topLevel[len(topLevel)-1]
	if !ps1InvokesDefined(last.text, defined) {
		return &TruncationError{
			File: file, Line: last.number, Text: last.text,
			Reason: "the last statement must call a function defined in this script",
		}
	}

	// Prelude directives were filtered out above and never reach topLevel, so
	// anything here other than the final invocation is a statement that would
	// run before the script had finished arriving.
	if len(topLevel) > 1 {
		offending := topLevel[0]

		return &TruncationError{
			File: file, Line: offending.number, Text: offending.text,
			Reason: "runs a statement at the top level, so a truncated download could execute it",
		}
	}

	return nil
}

// ps1InvokesDefined reports whether a statement calls a defined function.
func ps1InvokesDefined(statement string, defined map[string]bool) bool {
	match := ps1Invocation.FindStringSubmatch(strings.TrimSpace(statement))
	if match == nil {
		return false
	}

	if !defined[strings.ToLower(match[1])] {
		return false
	}

	// A pipeline or a statement separator after the call would run regardless
	// of whether the call itself completed arriving.
	for _, chain := range []string{"|", ";", "&&", "||"} {
		if strings.Contains(statement, chain) {
			return false
		}
	}

	return true
}

// stripPowerShellComment removes a trailing line comment, and reports whether
// the line opens a block comment.
func stripPowerShellComment(line string) (string, bool) {
	var (
		quote  rune
		escape bool
	)

	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		switch {
		case escape:
			escape = false
		case r == '`':
			// PowerShell's escape character is the backtick.
			escape = true
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"':
			quote = r
		case r == '#':
			// A #Requires directive is a comment to PowerShell but is
			// meaningful here, so it is left in place for ps1Prelude.
			if strings.HasPrefix(strings.TrimSpace(string(runes[i:])), "#Requires") {
				return line, false
			}

			if i+1 < len(runes) && runes[i+1] == '>' {
				// A stray "#>" with no opening block comment.
				continue
			}

			if i+1 < len(runes) && runes[i+1] == '<' {
				// "#<" is not a thing; treat as a line comment.
				return string(runes[:i]), false
			}

			return string(runes[:i]), false
		case r == '<':
			if i+1 < len(runes) && runes[i+1] == '#' {
				return string(runes[:i]), true
			}
		}
	}

	return line, false
}

// parenDelta counts unquoted parentheses on a line.
func parenDelta(line string) int {
	var (
		delta  int
		quote  rune
		escape bool
	)

	for _, r := range line {
		switch {
		case escape:
			escape = false
		case r == '`' || r == '\\':
			escape = true
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"':
			quote = r
		case r == '(':
			delta++
		case r == ')':
			delta--
		}
	}

	return delta
}
