package bundle

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Truncation protection (§6.3).
//
// A connection that drops mid-download can hand a shell half a script, and
// `curl … | sh` will run that half. The defence is structural: all logic lives
// inside a function, and the function is invoked on the last line. A truncated
// download loses the invocation, so nothing runs.
//
//	main() {
//	    # install logic
//	}
//	main "$@"
//
// What this file checks is exactly that shape, and nothing more. It cannot
// verify that a script is safe, correct, or that its logic is genuinely
// confined to the wrapper - a script that passes can still do anything once
// invoked. What it does guarantee is that the script cannot do any of it until
// the last line has arrived.
//
// Because the check is a heuristic over shell syntax rather than a parse, it
// will occasionally be wrong about a legitimate script. Route.SkipTruncationCheck
// is the recorded way out; `bundle list` and the publish event both report it,
// so a bundle that opted out stays visible afterwards.

// TruncationError reports a script that failed the check.
//
// It carries the line it objected to, because "this script is not wrapped" is
// not actionable and "line 12 runs a command at the top level" is.
type TruncationError struct {
	// File is the archive path of the offending script.
	File string

	// Line is the 1-indexed line number, or 0 when the problem is the script
	// as a whole.
	Line int

	// Text is the offending line, trimmed.
	Text string

	// Reason says what is wrong.
	Reason string
}

func (e *TruncationError) Error() string {
	if e.Line == 0 {
		return fmt.Sprintf("%s: %s", e.File, e.Reason)
	}

	return fmt.Sprintf("%s:%d: %s: %q", e.File, e.Line, e.Reason, e.Text)
}

// ErrUncheckableScript is returned for a file whose language this package does
// not know how to check.
var ErrUncheckableScript = errors.New("bundle: no truncation check for this file type")

// ScriptKind is a language the truncation check understands.
type ScriptKind string

// The kinds checked.
const (
	KindShell      ScriptKind = "shell"
	KindPowerShell ScriptKind = "powershell"
	KindUnknown    ScriptKind = ""
)

// KindOf identifies a script's language from its route path and its contents.
//
// The extension decides, and a shebang is consulted when there is none - a
// route served at /install with `#!/bin/sh` is still a shell script, and
// skipping the check because the path had no suffix would be the wrong answer
// in the one direction that matters.
func KindOf(routePath string, content []byte) ScriptKind {
	switch strings.ToLower(path.Ext(routePath)) {
	case ".sh", ".bash", ".ksh":
		return KindShell
	case ".ps1":
		return KindPowerShell
	}

	first := firstLine(content)
	if strings.HasPrefix(first, "#!") {
		// Matching on the interpreter name rather than the whole line, so
		// `#!/usr/bin/env bash` and `#!/bin/sh` both land here.
		for _, shell := range []string{"bash", "/sh", "dash", "ksh", "zsh", "ash"} {
			if strings.Contains(first, shell) {
				return KindShell
			}
		}

		if strings.Contains(strings.ToLower(first), "pwsh") {
			return KindPowerShell
		}
	}

	return KindUnknown
}

// CheckTruncation verifies a script is wrapped so truncation cannot execute
// part of it.
func CheckTruncation(file, routePath string, content []byte) error {
	switch KindOf(routePath, content) {
	case KindShell:
		return checkShell(file, content)
	case KindPowerShell:
		return checkPowerShell(file, content)
	default:
		return fmt.Errorf("%w: %s", ErrUncheckableScript, file)
	}
}

// shellFunctionDef matches a shell function definition's opening line, in both
// the POSIX `name()` and the bash `function name` forms.
var shellFunctionDef = regexp.MustCompile(
	`^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_:.-]*)\s*(?:\(\s*\))?\s*\{\s*$`)

// shellPrelude matches top-level lines that cannot act on the system.
//
// Everything not matched here is treated as a command, which is the
// conservative direction: a new shell builtin that happens to be harmless gets
// rejected until it is added, whereas an allowlist that guesses would let a
// real command through.
var shellPrelude = regexp.MustCompile(
	`^\s*(?:` +
		// Shell options and umask.
		`set\s|shopt\s|umask\s` +
		// A plain assignment, including export/readonly/declare/typeset/local
		// forms. The value is checked separately for substitutions.
		`|(?:export|readonly|declare|typeset|local)\s+[A-Za-z_][A-Za-z0-9_]*=` +
		`|[A-Za-z_][A-Za-z0-9_]*=` +
		// A bare export of an already-set name runs nothing.
		`|export\s+[A-Za-z_][A-Za-z0-9_]*\s*$` +
		`)`)

// shellSubstitution matches a command substitution or backticks.
//
// An assignment is only inert if its value is a literal. `VERSION=$(curl …)`
// is an assignment that makes a network call, so it is a command for this
// check's purposes and must not pass as prelude.
var shellSubstitution = regexp.MustCompile(`\$\(|` + "`" + `|\$\{[^}]*[:=+?-]`)

// checkShell applies the structural check to a shell script.
func checkShell(file string, content []byte) error {
	lines := strings.Split(normaliseNewlines(string(content)), "\n")

	defined := map[string]bool{}
	var topLevel []numberedLine

	var (
		depth   int
		heredoc string
	)

	for i, raw := range lines {
		number := i + 1
		line := raw

		// Inside a heredoc nothing is code: its braces must not move the
		// nesting depth and its contents must not look like commands.
		if heredoc != "" {
			if strings.TrimSpace(line) == heredoc {
				heredoc = ""
			}

			continue
		}

		stripped := stripShellComment(line)
		trimmed := strings.TrimSpace(stripped)

		if trimmed == "" {
			continue
		}

		// A shebang is only meaningful on the first line.
		if number == 1 && strings.HasPrefix(trimmed, "#!") {
			continue
		}

		if delimiter, ok := heredocDelimiter(stripped); ok {
			heredoc = delimiter
		}

		if depth == 0 {
			if match := shellFunctionDef.FindStringSubmatch(stripped); match != nil {
				defined[match[1]] = true
				depth += braceDelta(stripped)

				continue
			}

			topLevel = append(topLevel, numberedLine{number: number, text: trimmed})
		}

		depth += braceDelta(stripped)
		if depth < 0 {
			// Unbalanced braces mean the structure cannot be reasoned about,
			// so the check refuses rather than guessing.
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

	// The last top-level statement must be the invocation.
	last := topLevel[len(topLevel)-1]
	if !invokesDefined(last.text, defined) {
		return &TruncationError{
			File: file, Line: last.number, Text: last.text,
			Reason: "the last statement must call a function defined in this script",
		}
	}

	// Everything before it must be inert.
	for _, line := range topLevel[:len(topLevel)-1] {
		if !shellPrelude.MatchString(line.text) {
			return &TruncationError{
				File: file, Line: line.number, Text: line.text,
				Reason: "runs a command at the top level, so a truncated download could execute it",
			}
		}

		if shellSubstitution.MatchString(line.text) {
			return &TruncationError{
				File: file, Line: line.number, Text: line.text,
				Reason: "assigns from a command substitution, which executes at the top level",
			}
		}
	}

	return nil
}

// numberedLine is a source line with its 1-indexed number.
type numberedLine struct {
	number int
	text   string
}

// invokesDefined reports whether a statement calls one of the defined
// functions.
//
// The first word must be a defined name. `main "$@"` passes; `main && other`
// does not, because the `&&` makes the tail a second statement whose execution
// does not depend on the full script having arrived.
func invokesDefined(statement string, defined map[string]bool) bool {
	// A leading `&` or `exec` prefix is a call either way.
	statement = strings.TrimPrefix(strings.TrimSpace(statement), "exec ")

	fields := strings.Fields(statement)
	if len(fields) == 0 {
		return false
	}

	if !defined[fields[0]] {
		return false
	}

	// Anything that chains a second statement onto the call defeats the point.
	for _, chain := range []string{"&&", "||", ";", "|", "&"} {
		if strings.Contains(statement, chain) {
			return false
		}
	}

	return true
}

// braceDelta counts unquoted braces on a line.
//
// Quoted and escaped braces are skipped, because `echo "{"` must not look like
// the start of a block. This is a heuristic, not a parse, and it is the part of
// the check most likely to be wrong about an unusual script - which is what
// SkipTruncationCheck is for.
func braceDelta(line string) int {
	var (
		delta  int
		quote  rune
		escape bool
	)

	for _, r := range line {
		switch {
		case escape:
			escape = false
		case r == '\\':
			escape = true
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"':
			quote = r
		case r == '{':
			delta++
		case r == '}':
			delta--
		}
	}

	return delta
}

// stripShellComment removes an unquoted trailing comment.
func stripShellComment(line string) string {
	var (
		quote  rune
		escape bool
	)

	for i, r := range line {
		switch {
		case escape:
			escape = false
		case r == '\\':
			escape = true
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"':
			quote = r
		case r == '#':
			// A '#' only starts a comment at the start of a word.
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return line[:i]
			}
		}
	}

	return line
}

// heredocRe matches a heredoc introducer and captures its delimiter.
var heredocRe = regexp.MustCompile(`<<-?\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)

// heredocDelimiter reports whether a line opens a heredoc, and its delimiter.
func heredocDelimiter(line string) (string, bool) {
	// `<<<` is a bash here-string, not a heredoc, and consumes no following
	// lines.
	if strings.Contains(line, "<<<") {
		return "", false
	}

	match := heredocRe.FindStringSubmatch(line)
	if match == nil {
		return "", false
	}

	return match[1], true
}

// normaliseNewlines converts CRLF and CR to LF.
//
// A bundle written on Windows has CRLF line endings, and the check must see
// the same structure either way. The script itself is served verbatim; this
// normalisation is only for reading it.
func normaliseNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")

	return strings.ReplaceAll(s, "\r", "\n")
}

// firstLine returns the first line of content.
func firstLine(content []byte) string {
	text := normaliseNewlines(string(content))
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		return text[:index]
	}

	return text
}
