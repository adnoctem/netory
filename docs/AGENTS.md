# AGENTS.md - netory

netory is three Go services - `protean`, `signpost`, `pivot` - in one Bazel/Bzlmod monorepo, MIT
licensed, with no cgo. Linux is the only supported server platform; the CLIs are built for macOS
too, for the subcommands that need no server. Read
[CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and
[IMPLEMENTATION.md](IMPLEMENTATION.md) for build order and the decisions shared across all three.

The design documents in [`design/`](design/) are the **source of truth for scope, architecture and
decisions**. They are living documents: each closes with a §10 "Open Questions & Verification
Items", and **when you resolve one, update the document in the same change**.

## Repository tasks

| Task                        | Command                                            |
| --------------------------- | -------------------------------------------------- |
| Build everything            | `bazel build //...`                                |
| Test everything             | `bazel test //...`                                 |
| Test with the race detector | `bazel test //... --config=race`                   |
| Regenerate the BUILD files  | `bazel run //:gazelle`                             |
| Tidy the module graph       | `bazel mod tidy`                                   |
| Build the container images  | `bazel build --config=release //cmd/...:image`     |
| Load one image locally      | `bazel run --config=release //cmd/<service>:load`  |
| Build the release artifacts | `scripts/release-create.sh --version <version>`    |
| Verify a release builds     | `scripts/release-create.sh -v <version> --dry-run` |
| Run the hooks               | `pre-commit run --all-files`                       |
| Run the end-to-end tests    | `go test -tags e2e -timeout 10m ./tests/e2e/...`   |

Before committing or handing changed files back, run `pre-commit run --all-files`, resolve the
findings, and rerun after a hook modifies files. For implementation changes run
`bazel test //... --config=race`; for changes to the build or the packaging path finish with
`scripts/release-create.sh --version <version> --dry-run`.

Three things catch people out, in roughly this order:

- **Run gazelle after adding or moving a Go file, before `bazel test`.** A test file gazelle has not
  seen is not in any target, and `bazel test` then passes without running it. That has happened
  here: a test file written after the last gazelle run was absent from the committed target and the
  suite went green without it.
- **`--config=race` cannot be the default.** rules_go's race instrumentation requires cgo, and the
  release configuration disables it. CI runs both configurations; so should you.
- **The Valkey-backed suites share one server.** `pkg/kv/valkeykv`, `internal/pivot/app` and
  `internal/pivot/server` each take their own logical database, and each cleans up only its own key
  prefixes. Never add a `SCAN *` plus `DEL`: one did exactly that and deleted another suite's keys
  mid-run, which presented as a failure in the suite that was innocent.

## Architecture and public APIs

- `cmd/<service>` is a thin entrypoint and nothing else. Application code lives in
  `internal/<service>`, and anything two services share lives in `pkg/`.
- `pkg/` is the shared foundation: one `kv.Store` interface with a Badger and a Valkey
  implementation, and `pkg/kv/kvtest` is the conformance suite **every implementation must pass**.
  A new store is finished when that suite passes under `--config=race`, not when it compiles.
- Each service's user-facing documentation is `cmd/<service>/README.md`, beside its entrypoint. The
  design document says why the service is the way it is; the README says how to use it. Do not
  duplicate a design document into a README.
- The two JSON Schemas under `docs/schema/` are **generated** from the Go types that validate the
  documents they describe, through the shared `pkg/schema`. After changing a signpost manifest type
  or a pivot rule-document type, regenerate the committed file in the same change with
  `go test ./internal/<service>/<pkg> -run TestSchema -update`. A test fails if you forget, and a
  field added without declared bounds fails another one.
- Services hold credentials, so two layers must fail before anything is exposed. Keep it that way:
  do not collapse a check because another one already covers it.
- **No bundled defaults.** A configuration a service would install on an operator's behalf belongs
  in `docs/examples/` as a document they copy, read and edit - not in a Go constant. pivot used to
  carry a Shopware rule set as a `--preset`; it does not any more, and a new one should not appear.
  Examples are kept honest by tests that compile every file in that directory.
- Badger takes a single writer, so protean and signpost are single-replica by construction. pivot is
  the multi-replica one, and everything it stores is in Valkey.
- Valkey has **no encryption at rest**. Anything sensitive pivot stores is sealed with `pkg/seal`
  before it is written, under a key derived from the service secret.

## Conventions

- Go, formatted by `gofmt` and linted by golangci-lint with the repository's `.golangci.yml`. The
  standard library is the default choice: `log/slog` through `pkg/log` rather than a third-party
  logger, and `testify` for assertions because the suites already read that way.
- **No cgo.** The release configuration sets `pure`, so a cgo dependency does not merely offend a
  preference - it cannot be released. Check before proposing one: a library whose Go client is a
  wrapper around a C FFI (Valkey GLIDE, for instance) is disqualified for that reason alone.
- **Ask before adding any dependency no design document names.** This is explicit in all three
  design documents, and it applies to Go modules and Bazel modules alike.
- Comments explain why, not what. A comment that restates the line above it is noise; a comment
  recording a decision, a constraint or a hazard is the reason the next reader does not repeat a
  mistake. Where a test exists because of a specific bug, say which.
- Shell follows the shape libsh established and gopskit's scripts use: `set -euo pipefail`, the
  libsh preamble, `<domain>-<verb>[-<object>].sh` filenames with a matching `<domain>_<verb>::`
  function namespace, and a `#####` comment block over each function giving its Arguments, Outputs
  and Returns. shfmt's defaults decide the formatting.
- Prettier is authoritative for Markdown, JSON and YAML, and it renumbers lists, rewrites emphasis
  and reformats JSON. Write for it rather than fighting it, and run it before committing. Generated
  JSON under `docs/schema/` is excluded through `.prettierignore`.
- Conventional commits: `type(scope): summary`, imperative and lowercase, no trailing period.
  Types: `feat|fix|docs|refactor|test|chore|build|ci`. Scopes: a service name (`protean`,
  `signpost`, `pivot`), a shared package (`pkg/kv`, `pkg/event`), `build`, or `docs`. Explain the
  problem, the resulting behaviour and how it was checked. semantic-release derives the version from
  these, so a wrong type is a wrong release.
- netory is in 0.x: a breaking change takes the minor version, and the release script refuses
  anything that is not a plain `0.x.y`. Review that policy before graduating to 1.0.0.
- **Publishing is explicitly gated.** Do not push, tag or publish anything without the user's
  authorisation.

## Security review rules

- Never commit secrets, credentials or tokens. Fixtures are synthetic. The generated secrets in
  tests come from `secret.Generate()` and never leave the test process.
- Do not log a secret and do not put one in a process argument - that is why neither the Valkey
  password nor any other credential has a command-line flag. Encoding is not encryption.
- Each service takes exactly one secret and derives every key from it with HKDF under a
  purpose-specific label, so one compromised key reveals nothing about another. Never use the raw
  secret as a key.
- Never disable certificate verification, and never serve executable content over a connection that
  cannot be confirmed as encrypted - signpost answers 421 rather than guessing.
- An error message returned to a client says what failed, never which half of a check failed.
  Distinguishing "unknown client" from "wrong secret" turns one search space into two smaller ones.
- Verify downloaded content against an independently trusted digest before using it. Bazel's
  dependencies are digest-pinned, including the container base image, and that is deliberate.

## Layout

- `cmd/<service>/`: entrypoint plus that service's user-facing `README.md`.
- `internal/<service>/`: per-service application code.
- `pkg/`: code shared across all three services, with `pkg/kv/kvtest` as the store conformance
  suite and `pkg/schema` as the JSON Schema generator both document formats use.
- `scripts/bazel/image.bzl`: the container image macro all three services use.
- `tests/e2e/`: container-backed end-to-end tests, behind the `e2e` build tag.
- `scripts/`: `release-create.sh` builds the release artifacts and is a
  [libsh](https://github.com/adnoctem/libsh) consumer, so `LIBSH_DIR` has to point at an
  installation; `bazel-create-status.sh` produces the build stamps and deliberately needs nothing
  but Bash, Git and coreutils, because Bazel runs it on every build and reads its stdout as the
  stamp. `scripts/bazel/` holds the Starlark.
- `docs/`: this file, `CONTRIBUTING.md`, `IMPLEMENTATION.md`, `ACKNOWLEDGEMENTS.md`,
  `design/` (the per-service design documents), `docs/schema/` (generated JSON Schema) and
  `docs/examples/` (configuration an operator copies - **nothing here is compiled into a binary or
  installed by a service**; pivot ships no rule set at all).
- `dist/`: release output, ignored.
- This file lives at `docs/AGENTS.md`; the root `AGENTS.md` is a symlink. Edit this file.
