#!/usr/bin/env bash
#
# Create netory's release artifacts: every service built for each platform and architecture, a
# tarball per service and platform, one tarball per platform with all of them, and a SHA-256
# checksum file covering every tarball.
#
# semantic-release runs it before tagging; see .releaserc. Requires libsh (LIBSH_DIR) and Bazel.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
ROOT_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)

# libsh is installed on the machine, not vendored: see docs/CONTRIBUTING.md
if [[ -z ${LIBSH_DIR:-} || ! -r ${LIBSH_DIR}/lib.sh ]]; then
	printf 'Cannot read libsh at %s/lib.sh; install libsh and export LIBSH_DIR (see docs/CONTRIBUTING.md).\n' "${LIBSH_DIR:-<unset>}" >&2
	exit 1
fi
LIBSH_DIR=$(cd -P -- "${LIBSH_DIR}" && pwd)
# shellcheck source=/dev/null
. "${LIBSH_DIR}/lib.sh"
if ! declare -F lib::opt::parse >/dev/null || ! declare -F lib::log::print_success >/dev/null; then
	printf 'Incompatible libsh at %s: this script needs the option parser and intent logging of libsh 0.7.0 or newer.\n' "${LIBSH_DIR}" >&2
	exit 1
fi

# Every service is released for Linux, which is the only platform they are supported as servers on.
# The macOS builds are for the subcommands that need no server - `rules validate`, `bundle
# validate`, `secret generate`, `version` - which is what somebody runs on a laptop or in a CI job.
readonly DEFAULT_TARGETS="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64"
readonly BINARIES_QUERY='kind("go_binary", //cmd/...)'
readonly CHECKSUMS_FILE="CHECKSUMS_SHA256.txt"

# -------------------------
#   Flag spec
# -------------------------

# shellcheck disable=SC2034 # read by the dynamically loaded option parser
OPTS=(
	"-v,--version:version:1:optional"
	"-o,--output-dir:output_dir:1:optional"
	"-t,--targets:targets:1:optional"
	",--check-prerequisites:check_prerequisites:0:optional"
	",--dry-run:dry_run:0:optional"
	"-h,--help:help:0:optional"
)

# shellcheck disable=SC2034 # read by the dynamically loaded option parser
declare -A OPTS_HELP=(
	[version]="The release version stamped into the binaries (default: \$NETORY_VERSION, else git describe)"
	[output_dir]="Directory to create the artifacts in; replaced if it exists (default: <repository>/dist)"
	[targets]="Comma-separated <os>/<arch> pairs to build for (default: ${DEFAULT_TARGETS})"
	[check_prerequisites]="Check that the required commands are installed, then exit"
	[dry_run]="Build every target and verify the version, but write no artifacts"
	[help]="Show this help message and exit"
)

declare -A OPTS_VALUES=()

#######################################
# Check that the commands the release needs are installed.
# Arguments:
#   None
# Outputs:
#   One line per prerequisite.
# Returns:
#   0 if all were found, 1 otherwise.
#######################################
function release_create::prerequisites() {
	local prerequisites=('bazel' 'git' 'tar' 'sha256sum')

	for prerequisite in "${prerequisites[@]}"; do
		if ! lib::os::is_executable "${prerequisite}"; then
			lib::log::print_error "Could not find '${prerequisite}' in PATH. Please install it to proceed!"
			return 1
		fi

		lib::log::print_info "Found '${prerequisite}' in PATH."
	done

	lib::log::print_success "Found all prerequisites: '${prerequisites[*]}'."
}

#######################################
# Check the version against netory's release policy.
#
# netory is in 0.x: a breaking change takes the minor, so there is no 1.0.0 until the three
# services' command surfaces and stored formats have been reviewed as stable. The guard is here as
# well as in .releaserc because this script is also what a human runs by hand, and the hand-run
# path is the one without a commit analyser to say no.
# Arguments:
#   1 - the version to check
# Outputs:
#   An explanation on rejection.
# Returns:
#   0 if the version may be released, 1 otherwise.
#######################################
function release_create::check_version() {
	local version=$1

	if [[ ! ${version} =~ ^0\.[0-9]+\.[0-9]+$ ]]; then
		lib::log::print_error "Refusing to release '${version}': netory releases plain 0.x versions only."
		lib::log::print_error "Review the 0.x policy in docs/CONTRIBUTING.md before graduating to 1.0.0."
		return 1
	fi

	if [[ ${version} == 0.0.* ]]; then
		lib::log::print_error "Refusing to release '${version}': the first release is 0.1.0."
		return 1
	fi
}

#######################################
# Build every service for one target and copy the binaries into the staging directory.
# Arguments:
#   1 - GOOS to build for
#   2 - GOARCH to build for
#   3 - staging directory, or the empty string to build without copying
#   4+ - Bazel labels of the binaries
# Outputs:
#   Progress messages; Bazel's own output.
# Returns:
#   0 on success, 1 if the build or a copy failed.
#######################################
function release_create::build() {
	local os=$1 arch=$2 staging=$3
	shift 3
	local -a config=("--config=release" "--config=${os}_${arch}" "--stamp")

	lib::log::print_info "Building the netory services for ${os}/${arch}"
	if ! bazel build "${config[@]}" "$@"; then
		lib::log::print_error "Bazel could not build the services for ${os}/${arch}"
		return 1
	fi

	[[ -n ${staging} ]] || {
		lib::log::print_success "Verified the release build for ${os}/${arch}"
		return 0
	}

	# cquery rather than a path built from bazel-bin: rules_go's --platforms does not change the
	# output base, so every target writes to the same path and the last build would win. Asking
	# for the files of this configuration is what keeps the platforms apart.
	local label name output
	for label in "$@"; do
		name=${label##*:}
		output=$(bazel cquery "${config[@]}" --output=files "${label}" 2>/dev/null)
		install -m 0755 -- "${ROOT_DIR}/${output}" "${staging}/${name}" || return 1
	done

	lib::log::print_success "Built the netory services for ${os}/${arch}"
}

#######################################
# Package the staged binaries of one target: one tarball per service, and one with all of them,
# each including the LICENSE and the README.
# Arguments:
#   1 - GOOS
#   2 - GOARCH
#   3 - the release version
#   4 - staging directory
#   5 - output directory
#   6+ - service names
# Outputs:
#   Progress messages.
# Returns:
#   0 on success, 1 if tar failed.
#######################################
function release_create::package() {
	local os=$1 arch=$2 version=$3 staging=$4 output_dir=$5
	shift 5
	local name

	# One tarball per service, for operators who deploy a single one.
	for name in "$@"; do
		tar -czf "${output_dir}/${name}-${version}-${os}-${arch}.tar.gz" \
			-C "${staging}" "${name}" \
			-C "${ROOT_DIR}" LICENSE README.md || return 1
	done

	# And one combined tarball, since the three services share a monorepo and are commonly
	# deployed together.
	tar -czf "${output_dir}/netory-${version}-${os}-${arch}.tar.gz" \
		-C "${staging}" "$@" \
		-C "${ROOT_DIR}" LICENSE README.md || return 1

	lib::log::print_success "Packaged the ${os}/${arch} tarballs"
}

#######################################
# Main
#######################################
function release_create::main() {
	lib::opt::parse "$@" || return
	[[ ${OPTS_VALUES[help]:-} != 1 ]] || return 0

	release_create::prerequisites >/dev/null || return
	[[ ${OPTS_VALUES[check_prerequisites]:-} != 1 ]] || {
		release_create::prerequisites
		return
	}

	local output_dir=${OPTS_VALUES[output_dir]:-${ROOT_DIR}/dist}
	local dry_run=${OPTS_VALUES[dry_run]:-}
	local -a targets
	IFS=',' read -r -a targets <<<"${OPTS_VALUES[targets]:-${DEFAULT_TARGETS}}"

	# scripts/bazel-create-status.sh stamps the binaries with this version. Without it a release
	# would stamp itself wrong: semantic-release decides the version and then runs this script, so
	# `git describe` at that moment still answers with the previous tag plus a commit count.
	local version=${OPTS_VALUES[version]:-${NETORY_VERSION:-}}
	version=${version#v}
	if [[ -n ${version} ]]; then
		release_create::check_version "${version}" || return
		export NETORY_VERSION=${version}
	else
		version=$(git -C "${ROOT_DIR}" describe --tags --always --dirty 2>/dev/null || echo "0.0.0-dev")
		version=${version#v}
		lib::log::print_warn "No version given; deriving '${version}' from git. A release must pass --version."
	fi
	lib::log::print_info "Releasing version ${version}"

	cd -- "${ROOT_DIR}"

	local -a labels names
	mapfile -t labels < <(bazel query "${BINARIES_QUERY}" --output=label 2>/dev/null | sort -u)
	if lib::data::array_is_empty "${labels[@]+"${labels[@]}"}"; then
		lib::log::print_error "Bazel found no binaries to release"
		return 1
	fi
	local label
	for label in "${labels[@]}"; do
		names+=("${label##*:}")
	done

	local staging=""
	if [[ ${dry_run} != 1 ]]; then
		rm -rf -- "${output_dir}"
		staging="${output_dir}/tmp"
		mkdir -p -- "${staging}"
	fi

	local target os arch
	for target in "${targets[@]}"; do
		os=${target%%/*}
		arch=${target##*/}

		release_create::build "${os}" "${arch}" "${staging}" "${labels[@]}" || return

		[[ ${dry_run} != 1 ]] || continue

		release_create::package "${os}" "${arch}" "${version}" "${staging}" "${output_dir}" "${names[@]}" || {
			lib::log::print_error "Could not package the ${os}/${arch} tarballs"
			return 1
		}
	done

	if [[ ${dry_run} == 1 ]]; then
		lib::log::print_success "Verified version ${version} and the release build for ${targets[*]}"
		return 0
	fi

	# Relative names in the checksum file, so `sha256sum -c` works from the directory a user
	# unpacked the release into.
	(cd -- "${output_dir}" && sha256sum -- *.tar.gz >"${CHECKSUMS_FILE}") || {
		lib::log::print_error "Could not compute the checksums"
		return 1
	}
	rm -rf -- "${staging}"

	lib::log::print_success "Created the release artifacts for ${names[*]} in ${output_dir}"
}

release_create::main "$@"
