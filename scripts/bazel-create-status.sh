#!/usr/bin/env bash
#
# Emits key/value pairs consumed by Bazel's --workspace_status_command and
# substituted into go_library x_defs (see pkg/stamp/BUILD.bazel). Keys must be
# stable: renaming one silently turns the corresponding stamp back into its
# "redacted" default rather than failing the build.
#
# Every lookup degrades to "unknown" rather than failing. This script runs on
# every build, including in a fresh clone with no commits and in CI checkouts
# that are shallow or detached - a non-zero exit here aborts the whole build.
#
# It deliberately needs nothing but Bash, Git and coreutils - not libsh, unlike
# release-create.sh beside it. Two reasons: Bazel reads this script's stdout as
# the stamp, so anything else written there would be stamped into a binary; and
# it runs before anything is built, so requiring an installed library would
# make a plain `bazel build` depend on one.

set -o errexit
set -o nounset
set -o pipefail

# fallback echoes the output of a command, or a default when that command fails
# or prints nothing. Note that `cmd || echo default` is not enough: git
# rev-parse --abbrev-ref writes "HEAD" to stdout *and* exits non-zero outside a
# branch, which would emit two values for one key and corrupt the status file.
fallback() {
	local default="$1"
	shift

	local out
	if out=$("$@" 2>/dev/null) && [[ -n "$out" ]]; then
		printf '%s\n' "$out"
	else
		printf '%s\n' "$default"
	fi
}

ROOT=$(fallback "$PWD" git rev-parse --show-toplevel)

# The Go SDK version is declared once, in MODULE.bazel, so the stamped
# GO_VERSION cannot drift from the toolchain that actually did the compiling.
# STABLE_ prefixed keys are the ones Bazel treats as volatile-safe: a change
# in a STABLE_ value invalidates stamped actions, while a change in an
# unprefixed one does not. The version is the only key here that should force a
# rebuild when it moves; BUILD_DATE deliberately must not, or every build would
# be a cache miss.
# NETORY_VERSION overrides the derived version, and scripts/release.sh sets it
# from the version semantic-release decided on.
#
# Without it a release would stamp itself wrong: semantic-release runs its
# prepare step before the tag exists, so `git describe` at that moment answers
# with the *previous* tag plus a commit count. The artifacts for 0.2.0 would
# report 0.1.0-4-gdeadbee and the tarballs would be named after it.
echo STABLE_VERSION "${NETORY_VERSION:-$(fallback 0.0.0-dev git describe --tags --always --dirty)}"
echo GIT_COMMIT_SHA "$(fallback unknown git rev-parse --short=7 HEAD)"
echo GIT_BRANCH "$(fallback unknown git rev-parse --abbrev-ref HEAD)"
echo GO_VERSION "$(fallback unknown grep -Po '^go_sdk\.download\(version = "\K[0-9]+\.[0-9]+(\.[0-9]+)?' "$ROOT/MODULE.bazel")"
echo BUILD_DATE "$(fallback unknown date --rfc-3339=seconds)"
echo PLATFORM "$(fallback "$(uname -sr)" grep -Po "PRETTY_NAME=[\'\"]\K[^\"\']*" /etc/os-release)"
