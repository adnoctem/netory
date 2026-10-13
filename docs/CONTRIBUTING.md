# Ad Noctem Collective - `netory` Repository Contributing Guidelines

Contributions are welcome via GitHub's Pull Requests. This document covers the development workflow, the code
conventions and the release procedure.

Start with the [Architecture][architecture] for how the three services work and what they share. Each service's
README beside its entrypoint is its user documentation. Participation follows the [Code of Conduct][conduct];
report suspected vulnerabilities privately using the [Security Policy][security]. Open work is tracked in the
[TODO][todo].

## 🧰 Prerequisites

Develop on Linux. You need:

- Git and [bazelisk][bazelisk], which reads `.bazelversion` and fetches the matching Bazel;
- [`pre-commit`][precommit], and [Bun][bun] for Prettier;
- a Docker-compatible engine for the container images, the Valkey-backed tests and the end-to-end tests;
- a Go toolchain for the end-to-end tests, which run outside Bazel;
- [libsh][libsh] 0.7.0 or newer for the release script.

The Go SDK used by the build, every Go module, every Bazel rule set and the container base image are pinned in
`MODULE.bazel` and `go.mod` and fetched by Bazel.

```sh
pre-commit install
bazel build //...
bazel test //... --config=race
```

`scripts/release-create.sh` takes its option parsing, logging and prerequisite checks from libsh and finds it
through `LIBSH_DIR`. The script reports a missing or incompatible installation itself.

```sh
curl -fsSL https://raw.githubusercontent.com/adnoctem/libsh/v0.7.0/bin/install |
  bash -s -- --version v0.7.0
export PATH="${HOME}/.local/bin:${PATH}"
export LIBSH_DIR="$(libman path)"
```

Install a pinned release rather than `main`: libsh is pre-1.0 and its minor releases may break compatibility. CI
installs the same pinned version.

## 🗂️ Repository Layout

```text
cmd/<service>/            entrypoint, user-facing README and container image target
internal/<service>/       per-service application code
pkg/                      packages shared by the services
  kv/                     store interface
  kv/badgerkv/            Badger implementation (protean, signpost)
  kv/valkeykv/            Valkey implementation (pivot)
  kv/kvtest/              conformance suite every implementation must pass
  secret/                 service secret validation and HKDF derivation
  seal/                   authenticated encryption for values stored outside an encrypted store
  admin/                  Unix-socket admin server and client, peer credentials
  forwarded/              X-Forwarded-* parsing: client address and TLS state
  event/                  event bus with a persistent outbox, retries and claims
  notify/                 SMTP and HMAC-signed webhook notifiers
  backup/                 sealed backups to a filesystem or S3
  schema/                 JSON Schema generation from Go types
  log/                    log/slog wrapper
  stamp/                  link-time build metadata
tests/e2e/                container-backed end-to-end tests, behind the `e2e` tag
scripts/                  release-create.sh, bazel-create-status.sh, bazel/image.bzl
docs/                     project documentation, generated schemas and configuration examples
```

The Go module path is `github.com/adnoctem/netory`. Gazelle uses `go_naming_convention import_alias`, so every
package has a target named after its directory plus a `go_default_library` alias. Badger needs the
`gazelle:proto disable_global` override declared in `MODULE.bazel`; removing it breaks the build.

## ⚒️ Building and Testing

| Task                        | Command                                             |
| --------------------------- | --------------------------------------------------- |
| Build everything            | `bazel build //...`                                 |
| Test everything             | `bazel test //...`                                  |
| Test with the race detector | `bazel test //... --config=race`                    |
| Test one package            | `bazel test //internal/pivot/app:app_test`          |
| Regenerate the BUILD files  | `bazel run //:gazelle`                              |
| Tidy the module graph       | `bazel mod tidy`                                    |
| Build the container images  | `bazel build --config=release //cmd/...:image`      |
| Load an image locally       | `bazel run --config=release //cmd/pivot:load`       |
| Build the release artifacts | `scripts/release-create.sh --version <version>`     |
| Check that a release builds | `scripts/release-create.sh --version <v> --dry-run` |
| Run the end-to-end tests    | `go test -tags e2e -timeout 10m ./tests/e2e/...`    |
| Run every hook              | `pre-commit run --all-files`                        |

The race detector needs cgo and the release configuration disables it, so `--config=race` is a separate
configuration rather than the default. CI runs both; run both before submitting a change.

**Run `bazel run //:gazelle` after adding, moving or renaming a Go file, and before `bazel test`.** A test file
Gazelle has not seen belongs to no target, and `bazel test` passes without running it. Run `bazel mod tidy` after
changing `go.mod`.

Two suites need more than the Bazel sandbox offers and skip themselves when their dependency is missing:

```sh
# The Valkey store and pivot's state, against a real Valkey. CI runs one as a service container.
docker run --rm -d -p 6379:6379 valkey/valkey:9-alpine
VALKEY_TEST_ADDR=127.0.0.1:6379 bazel test //... --config=race

# The end-to-end tests: the real pivot binary, two replicas, a Valkey from testcontainers and a stub backend.
go test -tags e2e -timeout 10m ./tests/e2e/...
```

The Valkey-backed suites share one server. Each uses its own logical database - `pkg/kv/valkeykv` scopes itself by
key prefix, `internal/pivot/app` uses database 1, `internal/pivot/server` database 2 and the end-to-end stack
database 9 - and deletes only its own keys. Never clean up with a wildcard such as `SCAN *` and `DEL`: it deletes
keys another suite is using.

A new `kv.Store` implementation is complete when `pkg/kv/kvtest` passes against it under `--config=race`.

## 📝 Code Conventions

- Go is formatted by `gofmt` and linted by golangci-lint with `.golangci.yml`.
- Use the standard library by default: `log/slog` through `pkg/log`, `crypto/hkdf`, `net/smtp`. Tests use testify.
- Return errors wrapped with `%w`; do not panic. A message shown to an operator says what failed and what to do
  about it.
- Keep `cmd/<service>` a thin entrypoint. Application code belongs in `internal/<service>`; a package moves to
  `pkg/` only when a second service needs it.
- Third-party libraries sit behind interfaces this repository owns - the DNS provider interface, the notifier
  interface and the store - and never replace them.
- DNS providers and notifiers are compiled in and register at `init`. There is no runtime plugin loading.
- CLIs use Cobra with noun-verb ordering. `secret generate` and `version` must work without a running server, as
  must any `validate` command.
- Where a policy decision exists, deny by default.
- Comments explain why: the constraint, hazard or behaviour the code depends on. A test that exists because of a
  specific failure says which.
- Shell scripts follow libsh's shape: `set -euo pipefail`, the libsh preamble, `<domain>-<verb>[-<object>].sh` file
  names with a matching `<domain>_<verb>::` function namespace, and a comment block over each function giving its
  arguments, outputs and return values. shfmt's defaults decide formatting. `scripts/bazel-create-status.sh` uses
  only Bash, Git and coreutils, because Bazel runs it on every build and reads its output as the build stamp.

## 🔐 Secrets and Stored Credentials

Each service derives every key from its one secret with HKDF under a purpose-specific label. When adding a new
use for key material, add a new label; never reuse a key for two purposes and never use the raw secret as a key.

Anything sensitive that pivot stores goes through `pkg/seal` before it reaches Valkey, because Valkey has no
encryption at rest. Values that only need comparing - tokens, client secrets - are stored as SHA-256 hashes.
Never log a secret or accept one as a command-line flag; credentials arrive through the environment, a file or the
admin socket.

## 🧹 Formatting and Hooks

Shell is checked by shellcheck and formatted by shfmt. Prettier is authoritative for Markdown, JSON and YAML; it
renumbers ordered lists, rewrites emphasis and reformats JSON. Generated JSON under `docs/schema/` is excluded
through `.prettierignore`. Prettier runs through `bun x` and uses Bun's cache rather than a repository
`node_modules`.

```sh
pre-commit run --all-files
```

The hooks cover formatting, spelling, Markdown, secret scanning, workflow configuration, shell and the Go module.
They do not run the test suite. CI runs the same hooks plus the Bazel build and tests; a separate Super-Linter
workflow runs the broader shared checks.

zizmor's `ref-version-mismatch` audit needs the GitHub API. Without a token zizmor runs only its offline audits,
so export one for the hook to match CI:

```sh
export GH_TOKEN="$(gh auth token)"
```

Pin every GitHub action to the exact commit of an exact release, with the full version in the comment - `# v7.0.1`,
not `# v7`. A major-only comment names a moving tag and drifts from the pinned commit.

## 🧾 Generated Files

`docs/schema/signpost-manifest-v1.json` and `docs/schema/pivot-rules-v1.json` are generated from the Go types that
validate those documents. A test in each package fails if the committed file differs from the generated one.
Regenerate the matching file in the same change as the type:

```sh
go test ./internal/signpost/bundle -run TestSchema -update
go test ./internal/pivot/rules     -run TestSchema -update
```

Every field needs declared bounds and a description in the package's schema table; a test fails otherwise.
`pkg/schema.BaseURL` is the single source of the schemas' `$id`. Validate a changed schema with a JSON Schema draft
2020-12 validator as well - the in-repository tests check its shape, not its validity as a schema.

## 📚 Documentation

| Document                          | Audience          | Contents                                                     |
| --------------------------------- | ----------------- | ------------------------------------------------------------ |
| `README.md`                       | Users             | Overview and quick installation                              |
| `cmd/<service>/README.md`         | Operators         | Installing, configuring, running and deploying one service   |
| [`ARCHITECTURE.md`][architecture] | Users, developers | How the services work, what they share, known limitations    |
| `CONTRIBUTING.md`                 | Developers        | Workflow, conventions and the release procedure              |
| [`SECURITY.md`][security]         | Everyone          | Vulnerability reporting and trust boundaries                 |
| [`TODO.md`][todo]                 | Developers        | Open work and verification items                             |
| `AGENTS.md`                       | Coding agents     | The same ground, condensed; the root `AGENTS.md` links to it |

Documentation describes the project as it is. Update `ARCHITECTURE.md` and the affected service README in the
same change as the behaviour. Record open questions and unverified behaviour in `TODO.md`, and a limitation users
need to know about under the service's known limitations in `ARCHITECTURE.md`. Do not duplicate one document into
another; link to it.

Configuration a service would install on an operator's behalf belongs in `docs/examples/` as a document to copy,
not in a Go constant. Tests compile every example, so a new one is covered by adding it.

## 📦 Dependencies

**Ask before adding a dependency**, Go module or Bazel module, that is not already in `go.mod` or `MODULE.bazel`.
A candidate must:

- build with cgo disabled - the release configuration sets `pure`, so a module wrapping a C library cannot be
  released;
- carry a licence compatible with MIT.

Renovate proposes updates. rules_go and Gazelle are grouped, as are the container rules, because they are
verified together against the pinned Bazel release. A Badger update is labelled for a run of the `pkg/kv`
conformance suite, because `pkg/kv/badgerkv` relies on behaviour Badger does not document. Major GitHub-action
updates wait 14 days after release. Review the release notes of every major update before merging it.

## 🐳 Container Images

[`scripts/bazel/image.bzl`][image_macro] defines the images for all three services.

```sh
bazel run   --config=release //cmd/pivot:load      # load pivot:dev locally
bazel build --config=release //cmd/pivot:image     # the multi-arch index, as an OCI layout
bazel build --config=release //cmd/pivot:tarball   # docker-format tarball, no registry needed
```

Published images are built with `--config=release`. Without it the image contains a debug build, which is useful
when debugging inside the image. Inspect a changed image's layer listing - ownership, modes and paths - rather
than relying on it building.

## 🚀 Releases

semantic-release generates `CHANGELOG.md` from the commits; do not edit it by hand. It decides the version and
passes it to `scripts/release-create.sh`, which checks it, builds one static executable per service for
`linux/{amd64,arm64}` and `darwin/{amd64,arm64}`, packages the tarballs and writes the checksums. The
[Architecture][architecture_artifacts] describes the artifacts.

The version reaches each binary's `version` output through `NETORY_VERSION`, which the release script sets. Without
it the build stamp comes from `git describe`.

netory is in 0.x. Features and breaking changes take the minor version, fixes take the patch, and documentation,
refactoring and test commits release nothing. The release script accepts only a plain `0.x.y`; `.releaserc` applies
the same rule. Review both before releasing 1.0.0.

**Releasing is manual and gated.** The Release workflow does nothing unless `NETORY_RELEASE_ENABLED` is `true` in
the repository's Actions variables and the workflow is dispatched. Testing dispatches it after a successful run on
`main` or `next`, passing the commit it tested, and Release refuses to continue if the branch has advanced since.
Both branches are release branches; neither is a prerelease branch.

Release configuration:

- The container images are pushed with the run's own `GITHUB_TOKEN`, under `packages: write` held only by the
  image job.
- `ANC_GITHUB_TOKEN`, an optional Actions secret, is used when branch rules require a dedicated release identity;
  that identity must be allowed to push the changelog commit and the release tag.
- `NETORY_RELEASE_ENABLED` is the gate.

The workflow's `bootstrap` input publishes exactly 0.1.0 on a repository with no version tags. It refuses to run
once a `v*` tag exists and is not a retry mechanism.

```sh
scripts/release-create.sh --check-prerequisites       # what the script needs on the machine
scripts/release-create.sh --version 0.2.0 --dry-run   # builds everything, writes nothing
scripts/release-create.sh --version 0.2.0             # the artifacts, under dist/
```

### Completing a Partial Release

Publication is not transactional: a tag, the release assets and three images cannot land or fail together. The
workflow keeps `dist/` as an artifact for 14 days, including on failure, so a partial release is completed rather
than rebuilt; a rebuild produces different bytes under a version that may already have been downloaded.

Inspect what exists and complete only what is missing: attach the retained assets with `gh release upload`, or
re-push one image with `bazel run --config=release --stamp //cmd/<service>:push -- --tag <version>`. Never
overwrite a published version.

## ℹ️ Commit Message Format

`type(scope): summary`, imperative and lowercase, with no trailing period. Types:
`feat|fix|docs|refactor|test|chore|build|ci`. Scopes: a service (`protean`, `signpost`, `pivot`), a shared package
(`pkg/kv`, `pkg/event`, …), `build`, or `docs`. The body explains the problem, the resulting behaviour and how it
was checked. Mark an intentional compatibility change with a `BREAKING CHANGE` footer; in 0.x it takes the minor
version.

semantic-release derives the version from these messages, so a wrong type produces a wrong release.

<!-- File references -->

[architecture]: ARCHITECTURE.md
[architecture_artifacts]: ARCHITECTURE.md#release-artifacts
[conduct]: CODE_OF_CONDUCT.md
[security]: SECURITY.md
[todo]: TODO.md
[image_macro]: ../scripts/bazel/image.bzl

<!-- General links -->

[bazelisk]: https://github.com/bazelbuild/bazelisk
[precommit]: https://pre-commit.com
[bun]: https://bun.sh
[libsh]: https://github.com/adnoctem/libsh
