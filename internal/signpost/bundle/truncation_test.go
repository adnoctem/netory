package bundle_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/signpost/bundle"
)

// check is a shorthand for the common call shape.
func check(t *testing.T, routePath, script string) error {
	t.Helper()

	return bundle.CheckTruncation("scripts/"+strings.TrimPrefix(routePath, "/"), routePath, []byte(script))
}

// The required wrapper shape, in the variations a real installer uses.
func TestShellAcceptsWrappedScripts(t *testing.T) {
	asrt := assert.New(t)

	for name, script := range map[string]string{
		"the canonical form": `#!/bin/sh
main() {
    echo installing
}
main "$@"
`,
		"bash function keyword": `#!/usr/bin/env bash
function main {
    echo installing
}
main "$@"
`,
		"with a prelude": `#!/usr/bin/env bash
set -euo pipefail
umask 022
VERSION="1.2.3"
readonly PREFIX="/usr/local"
export INSTALL_LOG="/tmp/install.log"

main() {
    echo "installing ${VERSION} into ${PREFIX}"
}

main "$@"
`,
		"several functions": `#!/bin/sh
log() {
    echo "$@"
}
install_files() {
    log "copying"
}
main() {
    install_files
}
main "$@"
`,
		"comments everywhere": `#!/bin/sh
# This installer does a thing.
main() {
    # a comment with a brace { inside
    echo "a string with a brace } inside"
}
# Call it.
main "$@"
`,
		"a heredoc inside the function": `#!/bin/sh
main() {
    cat <<'EOF'
this { is } not code
main "$@"
EOF
}
main "$@"
`,
		"no arguments passed": `#!/bin/sh
main() {
    echo hi
}
main
`,
		"CRLF line endings": "#!/bin/sh\r\nmain() {\r\n    echo hi\r\n}\r\nmain \"$@\"\r\n",
		"no trailing newline": `#!/bin/sh
main() {
    echo hi
}
main "$@"`,
		"nested braces": `#!/bin/sh
main() {
    if true; then
        for f in a b c; do
            echo "$f"
        done
    fi
}
main "$@"
`,
	} {
		asrt.NoError(check(t, "/install.sh", script), name)
	}
}

// The failures that matter: anything that could run before the last line has
// arrived.
func TestShellRejectsUnwrappedScripts(t *testing.T) {
	asrt := assert.New(t)

	for name, script := range map[string]string{
		"no function at all": `#!/bin/sh
echo installing
curl -fsSL https://example.org/thing | tar xz
`,
		"a command before the call": `#!/bin/sh
main() {
    echo installing
}
rm -rf /tmp/stale
main "$@"
`,
		"a command after the call": `#!/bin/sh
main() {
    echo installing
}
main "$@"
echo done
`,
		"defined but never called": `#!/bin/sh
main() {
    echo installing
}
`,
		"the call is chained": `#!/bin/sh
main() {
    echo installing
}
main "$@" && echo done
`,
		"the call is piped": `#!/bin/sh
main() {
    echo installing
}
main "$@" | tee /tmp/log
`,
		"calls something undefined": `#!/bin/sh
helper() {
    echo hi
}
main "$@"
`,
		"assignment from a command substitution": `#!/bin/sh
VERSION=$(curl -fsSL https://example.org/version)
main() {
    echo "$VERSION"
}
main "$@"
`,
		"assignment from backticks": "#!/bin/sh\nVERSION=`date`\nmain() {\n    echo hi\n}\nmain \"$@\"\n",
		"unbalanced braces": `#!/bin/sh
main() {
    echo installing
main "$@"
`,
	} {
		err := check(t, "/install.sh", script)
		asrt.Error(err, name)

		if err != nil {
			var truncErr *bundle.TruncationError
			asrt.ErrorAs(err, &truncErr, name)
			asrt.NotEmpty(truncErr.Reason, name)
		}
	}
}

// The error has to name the line, because "this script is not wrapped" is not
// actionable and "line 5 runs a command at the top level" is.
func TestTruncationErrorNamesTheLine(t *testing.T) {
	asrt := assert.New(t)

	err := check(t, "/install.sh", `#!/bin/sh
main() {
    echo installing
}
rm -rf /tmp/stale
main "$@"
`)
	require.Error(t, err)

	var truncErr *bundle.TruncationError
	require.ErrorAs(t, err, &truncErr)

	asrt.Equal(5, truncErr.Line)
	asrt.Equal("rm -rf /tmp/stale", truncErr.Text)
	asrt.Contains(truncErr.Error(), "scripts/install.sh:5")
	asrt.Contains(truncErr.Error(), "top level")
}

// The actual threat, stated as a test: truncating a passing script at any
// point must leave something that cannot execute the payload.
//
// Every prefix of a wrapped script either fails to parse or is missing the
// invocation, so nothing in the function body runs. That is the whole property
// the check buys.
func TestTruncatedWrappedScriptNeverInvokes(t *testing.T) {
	asrt := assert.New(t)

	script := `#!/bin/sh
set -eu
main() {
    rm -rf /important
}
main "$@"
`
	require.NoError(t, check(t, "/install.sh", script))

	lines := strings.Split(strings.TrimSuffix(script, "\n"), "\n")

	// Every strict prefix of the script.
	for i := 1; i < len(lines); i++ {
		prefix := strings.Join(lines[:i], "\n")

		asrt.NotContains(prefix+"\n", "\nmain \"$@\"",
			"a prefix cut at line %d contains the invocation, so truncation could execute the body", i)
	}

	// And the full script does contain it, so the test is not vacuous.
	asrt.Contains(script, "\nmain \"$@\"")
}

func TestPowerShellAcceptsWrappedScripts(t *testing.T) {
	asrt := assert.New(t)

	for name, script := range map[string]string{
		"the canonical form": `function Main {
    Write-Host "installing"
}
Main @args
`,
		"with a prelude": `#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Main {
    Write-Host "installing"
}

Main @args
`,
		"several functions": `function Write-Log {
    param([string]$Message)
    Write-Host $Message
}

function Main {
    Write-Log "installing"
}

Main
`,
		"ampersand invocation": `function Main {
    Write-Host "hi"
}
& Main
`,
		"a verb-noun function name": `function Install-Thing {
    Write-Host "hi"
}
Install-Thing
`,
		"block comments": `<#
.SYNOPSIS
    An installer. It mentions { braces } in the comment.
#>
function Main {
    Write-Host "hi"
}
Main @args
`,
		"a param block": `[CmdletBinding()]
param(
    [string]$Prefix = "C:\Program Files",
    [switch]$Force
)

function Main {
    Write-Host $Prefix
}

Main @args
`,
		"trailing line comment": `function Main {
    Write-Host "hi"  # inline
}
Main @args  # go
`,
		"CRLF": "function Main {\r\n    Write-Host \"hi\"\r\n}\r\nMain @args\r\n",
	} {
		asrt.NoError(check(t, "/install.ps1", script), name)
	}
}

func TestPowerShellRejectsUnwrappedScripts(t *testing.T) {
	asrt := assert.New(t)

	for name, script := range map[string]string{
		"no function": `Write-Host "installing"
Invoke-WebRequest https://example.org/thing -OutFile thing.zip
`,
		// The exact case from the design note: valid syntax after truncation,
		// and destructive.
		"a statement before the call": `function Main {
    Write-Host "installing"
}
Remove-Item -Recurse C:\target
Main @args
`,
		"a statement after the call": `function Main {
    Write-Host "installing"
}
Main @args
Write-Host "done"
`,
		"defined but never called": `function Main {
    Write-Host "installing"
}
`,
		"the call is piped": `function Main {
    Write-Host "installing"
}
Main @args | Out-File log.txt
`,
		"calls something undefined": `function Helper {
    Write-Host "hi"
}
Main @args
`,
		"preference set from a subexpression": `$ErrorActionPreference = $(Get-Something)
function Main {
    Write-Host "hi"
}
Main @args
`,
		"unbalanced braces": `function Main {
    Write-Host "installing"
Main @args
`,
	} {
		err := check(t, "/install.ps1", script)
		asrt.Error(err, name)
	}
}

// The language is decided by extension, and by shebang when there is none - a
// route served at /install with #!/bin/sh is still a shell script, and
// skipping the check because the path had no suffix would be wrong in the one
// direction that matters.
func TestKindOf(t *testing.T) {
	asrt := assert.New(t)

	for _, tc := range []struct {
		path    string
		content string
		want    bundle.ScriptKind
	}{
		{"/install.sh", "", bundle.KindShell},
		{"/install.bash", "", bundle.KindShell},
		{"/install.ps1", "", bundle.KindPowerShell},
		{"/install", "#!/bin/sh\n", bundle.KindShell},
		{"/install", "#!/usr/bin/env bash\n", bundle.KindShell},
		{"/install", "#!/usr/bin/env pwsh\n", bundle.KindPowerShell},
		{"/data.json", `{"a":1}`, bundle.KindUnknown},
		{"/install", "no shebang here\n", bundle.KindUnknown},
	} {
		asrt.Equal(tc.want, bundle.KindOf(tc.path, []byte(tc.content)), "%s", tc.path)
	}
}

// A file whose language the check does not know is reported as uncheckable
// rather than quietly passing. The publish path decides what to do about that;
// silently treating it as checked would be the wrong default.
func TestUncheckableFileIsReported(t *testing.T) {
	asrt := assert.New(t)

	err := check(t, "/data.json", `{"version":1}`)
	asrt.ErrorIs(err, bundle.ErrUncheckableScript)
}

// A brace inside a quoted string must not be read as a block, or an ordinary
// script would be rejected for no reason.
func TestBracesInStringsDoNotConfuseTheCheck(t *testing.T) {
	asrt := assert.New(t)

	asrt.NoError(check(t, "/install.sh", `#!/bin/sh
main() {
    echo "{"
    echo '}'
    printf '%s\n' "{{}}"
}
main "$@"
`))
}

// An unterminated heredoc must not let its contents masquerade as a top-level
// invocation.
func TestHeredocContentsAreNotCode(t *testing.T) {
	asrt := assert.New(t)

	// The heredoc body contains what looks like a definition and a call. If
	// the check read them as code it would accept a script whose real top
	// level is a bare `cat`.
	err := check(t, "/install.sh", `#!/bin/sh
cat <<'EOF'
main() {
    echo nope
}
main "$@"
EOF
`)
	asrt.Error(err, "the heredoc body must not satisfy the check")
}
