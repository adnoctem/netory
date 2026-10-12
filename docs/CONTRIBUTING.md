# Contributing

netory is three Go services - `protean`, `signpost`, `pivot` - in one Bazel/Bzlmod monorepo. Each
has a design document in [`design/`](design/), which is the source of truth for its scope and
architecture, and a README beside its entrypoint, which is how to run it.
[IMPLEMENTATION.md](IMPLEMENTATION.md) covers build order and the decisions shared across all three.

## Prerequisites

Develop on Linux. You need Git, [bazelisk](https://github.com/bazelbuild/bazelisk) (which reads
`.bazelversion` and fetches the right Bazel itself), `pre-commit`, [Bun](https://bun.sh) for
Prettier, a Docker-compatible engine for the container and end-to-end work, a Go toolchain for the
end-to-end tests, and [libsh](https://github.com/adnoctem/libsh) for the release script. Everything
else - the Go SDK the build compiles with, every Go module, every
Bazel rule set, the container base image - is pinned in `MODULE.bazel` and `go.mod` and fetched by
Bazel.

```sh
pre-commit install
bazel build //...
bazel test //... --config=race
```

`scripts/release-create.sh` is a libsh consumer: it takes its option parsing, logging and
prerequisite checks from the shared library rather than carrying its own copies, which is the
arrangement gopskit uses as well. Install it once and export `LIBSH_DIR`; the script says so itself
if the variable is unset or points at nothing readable.

```sh
curl -fsSL https://raw.githubusercontent.com/adnoctem/libsh/v0.7.0/bin/install |
  bash -s -- --version v0.7.0
export PATH="${HOME}/.local/bin:${PATH}"
export LIBSH_DIR="$(libman path)"
```

Pin it rather than tracking `main`. libsh is 0.x and says outright that it ships breaking changes
without a major bump, so an unpinned install lets an upstream release break a release here. CI
installs the same pinned version, from the installer at that same tag, and Renovate watches the pin.

`scripts/bazel-create-status.sh` deliberately does **not** use libsh. Bazel runs it for every build
and reads its standard output as the build stamp, so anything else written there would be stamped
into a binary - and the library would have to be installed before anything could be built at all. It
needs nothing but Bash, Git and coreutils.

The Go version is declared once, in `MODULE.bazel`; `go.mod` carries the same one, and the status
script reads it from `MODULE.bazel` so a stamped binary cannot report a toolchain that did not
compile it.

## Daily workflow

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

`--config=race` is not the default because rules_go's race instrumentation requires cgo, which the
release configuration deliberately disables. CI runs both, and so should you before handing work
back.

**Run `bazel run //:gazelle` after adding, moving or renaming a Go file, and before `bazel test`.**
A test file gazelle has not seen belongs to no target, so `bazel test` passes without running it.
That is not hypothetical - it happened here, and the suite went green with four tests that were
never executed.

Two suites need more than the Bazel sandbox offers, and both skip themselves rather than fail when
it is missing:

```sh
# pivot's store, against a real Valkey. CI runs one as a service container.
docker run --rm -d -p 6379:6379 valkey/valkey:8-alpine
VALKEY_TEST_ADDR=127.0.0.1:6379 bazel test //... --config=race

# The end-to-end tests: the real binaries, a Valkey from testcontainers, and a
# backend. Outside Bazel, because they need a Docker socket and a Go toolchain.
go test -tags e2e -timeout 10m ./tests/e2e/...
```

The Valkey-backed suites share one server, so each takes its own logical database - `pkg/kv/valkeykv`
scopes itself by key prefix, `internal/pivot/app` uses database 1, `internal/pivot/server` database
2, the end-to-end stack database 9 - and each deletes only its own prefixes. Never add a wildcard
flush: one did, and it deleted another suite's keys mid-run, which presented as a failure in the
suite that was innocent.

## Formatting and hooks

Go is formatted by `gofmt` and linted by golangci-lint with `.golangci.yml`. Shell is checked by
shellcheck and formatted by shfmt. Prettier is authoritative for Markdown, JSON and YAML - it
renumbers lists, rewrites emphasis and reformats JSON, so write for it rather than against it.
Generated JSON under `docs/schema/` is excluded through `.prettierignore`. Prettier runs unpinned
through `bun x` and uses Bun's cache rather than a repository `node_modules`.

```sh
pre-commit run --all-files
```

The hooks cover formatting, spelling, Markdown, secret scanning, workflow configuration, shell and
the Go module. They do not run the test suite on every commit. CI runs the same hooks plus the
Bazel build and tests; a separate Super-Linter workflow keeps the broader shared checks.

One hook is weaker locally than in CI unless you help it. zizmor's `ref-version-mismatch` audit
checks that an action's pinned SHA is the commit its version comment names, and that needs the
GitHub API - so without a token zizmor runs its offline audits only, passes, and the same check
fails in Super-Linter afterwards. That has happened here. Export a token and the hook matches CI:

```sh
export GH_TOKEN="$(gh auth token)"
```

Pin every action to the exact commit of an exact release, with the full version in the comment -
`# v7.0.1`, not `# v7`. A major-only comment names a moving tag, so the pin and the comment drift
apart the moment that tag moves, which is precisely what the audit reports.

## Generated files

Two documents under `docs/schema/` are generated from the Go types that validate them, not written:
signpost's bundle manifest schema and pivot's rule document schema. They are committed because that
is what an editor and a CI job can point at, and a test in each package fails if the committed file
and the generated one differ.

```sh
go test ./internal/signpost/bundle -run TestSchema -update
go test ./internal/pivot/rules     -run TestSchema -update
```

Run the matching one after changing a manifest or rule-document type, in the same commit. The
generator lives in [`pkg/schema`](../pkg/schema/schema.go) and is shared, so a field added without
declaring its bounds fails a test rather than quietly appearing in a schema as an unconstrained
value. `pkg/schema.BaseURL` is the one place the schemas' `$id` is built from.

Neither schema is the authority on whether a document is usable. Both describe a well-formed
document; the checks JSON Schema cannot express - a regex that has to compile, a total entry count
across two arrays, a file that has to exist inside an archive - stay in Go, which is what
`signpost bundle validate` and `pivot rules validate` run.

## Dependencies

**Ask before adding any dependency no design document names.** This holds for Go modules and Bazel
modules alike, and it is written into all three design documents.

Two constraints rule candidates out before taste does:

- **No cgo.** The release configuration sets `pure`, so a module whose Go client wraps a C library
  cannot be released at all. Valkey's own GLIDE client is the worked example: its Go package links
  `libglide_ffi`, which is why `valkey-go` is the Valkey client here.
- **The licence has to be compatible with MIT.**

Renovate proposes updates and groups the ones that have to move together - rules_go with gazelle,
the container rules as a set - because those were verified together against the pinned Bazel LTS,
and bumping one alone is how that verification quietly stops holding. A Badger bump carries a label
asking for the `pkg/kv` conformance suite to be looked at rather than just a green tick, because
`pkg/kv/badgerkv` depends on behaviour Badger's API does not document.

## Container images

All three services publish to `ghcr.io/adnoctem/<service>` as multi-architecture images covering
`linux/amd64` and `linux/arm64`. [`scripts/bazel/image.bzl`](../scripts/bazel/image.bzl) defines them once for all
three; each service's README covers its own volumes, probes and a Kubernetes manifest.

```sh
bazel run   --config=release //cmd/pivot:load      # load pivot:dev locally
bazel build --config=release //cmd/pivot:image     # the multi-arch index, as an OCI layout
bazel build --config=release //cmd/pivot:tarball   # docker-format tarball, no registry needed
```

`--config=release` matters: it is the configuration the published images are built in, so without it
the image carries a debug build nearly twice the size. Leave it off when the reason you are building
an image is to debug something inside it.

## Releases

Semantic-release generates `CHANGELOG.md` from the commits; do not maintain it by hand. It decides
the version and hands it to `scripts/release-create.sh`, which verifies it, builds one static
executable per service per target, packages the tarballs and writes the checksums. The targets are
`linux/{amd64,arm64}` and `darwin/{amd64,arm64}`: Linux is the only platform the services are
supported on as servers, and the macOS builds are for the subcommands that need no server -
`rules validate`, `bundle validate`, `secret generate`, `version`. None of that needs a macOS SDK,
because the release configuration sets `pure` and the cross-build is pure Go.

The version reaches the binaries' own `version` output through the status script, which takes
`NETORY_VERSION` when the release sets it - without that a release would stamp itself with
`git describe`, which at prepare time still answers with the _previous_ tag.

netory is in 0.x. Features and breaking changes take the minor version, fixes take the patch, and
documentation, refactoring and test commits release nothing. The release script accepts only a
plain `0.x.y` and refuses `1.0.0`; `.releaserc` applies the same rule to what semantic-release
proposes. Review both before graduating to 1.0.0.

**Releasing is manual and gated.** The Release workflow does nothing unless
`NETORY_RELEASE_ENABLED` is `true` in the repository's Actions variables and somebody dispatches it.
Testing dispatches it automatically after a successful run on `main` or `next` and passes the commit
it tested; Release refuses to continue if the branch has advanced since. Both branches are release
branches, and neither is a prerelease branch.

Before enabling publication, configure:

- Nothing for the container images. They go to GHCR through the run's own `GITHUB_TOKEN`, under
  `packages: write` held by that one job.
- Optionally `ANC_GITHUB_TOKEN`, an Actions secret, when branch rules require a dedicated release
  identity; otherwise the workflow uses `GITHUB_TOKEN`. That identity has to be allowed to push the
  changelog commit and the release tag under the repository's branch rules.
- `NETORY_RELEASE_ENABLED=true`, an Actions variable, last - it is the gate.

### The first release

Semantic-release cannot produce it: with no version tag to measure from it proposes 1.0.0, which the
0.x guard refuses. Dispatch Release on `main`, pass the tested commit as `sha`, and select
`bootstrap`. That path builds and publishes exactly 0.1.0, creates the matching `v0.1.0` tag and
GitHub release with the tarballs and checksums attached, and then the image job pushes the three
images. It refuses any other branch and any pre-existing `v*` tag.

`CHANGELOG.md` starts with the release after it: the bootstrap path does not run semantic-release,
so the 0.1.0 notes are the ones GitHub generates from the commits. Leave `bootstrap` off afterwards.
It is not a retry mechanism.

```sh
scripts/release-create.sh --check-prerequisites       # what the script needs on the machine
scripts/release-create.sh --version 0.1.0 --dry-run   # builds everything, writes nothing
scripts/release-create.sh --version 0.1.0             # the artifacts, under dist/
```

### When a release goes wrong halfway

Publication is not transactional: a tag, a set of release assets and three images in a registry
cannot all land or all fail together. The workflow keeps `dist/` as an artifact for 14 days,
including on failure, so a partial release can be finished rather than rebuilt - a rebuild produces
different bytes under a version somebody may already have downloaded.

Inspect what exists, then complete only what is missing: attach the retained assets to the release
with `gh release upload`, or re-push one image with
`bazel run --config=release --stamp //cmd/<service>:push -- --tag <version>`. Do not overwrite a
version that is already published, and do not re-run `bootstrap`.

## Commit conventions

`type(scope): summary`, imperative and lowercase, with no trailing period. Types:
`feat|fix|docs|refactor|test|chore|build|ci`. Scopes: a service (`protean`, `signpost`, `pivot`), a
shared package (`pkg/kv`, `pkg/event`, …), `build`, or `docs`. Write a body explaining the problem,
the resulting behaviour and how it was checked. Use a `BREAKING CHANGE` footer when a compatibility
change is intentional - during 0.x it takes the minor version rather than the major.

semantic-release derives the version from these, so a `feat` that is really a `fix` is a wrong
release rather than a style slip.

## Design documents

The design documents are living. Each closes with a §10 "Open Questions & Verification Items", and
**when you resolve one, update the document in the same change**. A design document that still
poses a question the code has already answered is worse than no document, because the next reader
trusts it.

`[[name]]` inside a design document is an Obsidian wiki-link to `docs/design/name.md`.
