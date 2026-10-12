# netory

Three self-hosted network services in one Bazel monorepo.

| Service    | What it does                                                | State store | Status |
| ---------- | ----------------------------------------------------------- | ----------- | ------ |
| `protean`  | Self-hosted dynDNS control plane, DynDNS2-compatible        | Badger      | built  |
| `signpost` | Public script router for the `curl … \| sh` install pattern | Badger      | built  |
| `pivot`    | Transparent API proxy, Shopware 6 Admin API first           | Valkey      | built  |

Each service has two documents. The design document in [`docs/design/`](docs/design/) is the source
of truth for its scope and architecture; the README beside its entrypoint —
[`cmd/protean/README.md`](cmd/protean/README.md), [`cmd/signpost/README.md`](cmd/signpost/README.md),
[`cmd/pivot/README.md`](cmd/pivot/README.md) — is how to run it, and is where an operator should
start. [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) covers build order and the decisions shared
across all three.

Linux is the only supported server platform. The CLIs are also built for macOS, for the
subcommands that need no server - `rules validate`, `bundle validate`, `secret generate`,
`version`. No Windows binaries are shipped.

## Container images

All three are published to `ghcr.io/adnoctem/<service>` on every release, as multi-architecture
images covering `linux/amd64` and `linux/arm64`. They run as uid 65532 on a digest-pinned
`distroless/static` base and contain the service binary, a CA bundle and nothing else — no shell, no
package manager.

```sh
bazel run   --config=release //cmd/pivot:load      # load pivot:dev locally
bazel build --config=release //cmd/pivot:image     # the multi-arch index, as an OCI layout
bazel build --config=release //cmd/pivot:tarball   # docker-format tarball, for a registry-less cluster
```

`--config=release` is the configuration the published images are built in — the same one the
released executables use, so the binary in the image is optimised and stripped rather than a debug
build nearly twice the size.

[`scripts/bazel/image.bzl`](scripts/bazel/image.bzl) defines them, once, for all three. Each service README covers
its own volumes, probes and a Kubernetes manifest.

## Repository layout

```text
cmd/<service>/          thin entrypoints, plus the user-facing README for that service
internal/<service>/     per-service application code
pkg/                    shared across all three services
  kv/                   store interface
  kv/badgerkv/          Badger implementation (protean, signpost)
  kv/valkeykv/          Valkey implementation (pivot)
  kv/kvtest/            conformance suite every implementation must pass
  secret/               <SERVICE>_SECRET validation + HKDF derivation
  admin/                Unix-socket admin server, client and peer credentials
  forwarded/            X-Forwarded-* parsing: client address and TLS state
  event/                event bus with a persistent outbox, retries and claims
  notify/               SMTP and HMAC-signed webhook notifiers
  schema/               JSON Schema generated from the Go types that validate a document
  seal/                 authenticated encryption for values stored elsewhere
  backup/               sealed backups to the filesystem or S3
  log/                  log/slog wrapper
  stamp/                link-time build metadata
tests/e2e/              container-backed end-to-end tests, behind the `e2e` tag
docs/design/            per-service design documents
docs/schema/            generated JSON Schema, consumed by editors and CI
docs/examples/          configuration to copy; nothing here is installed by a service
docs/AGENTS.md          repository rules for an agent; root AGENTS.md symlinks here
docs/CONTRIBUTING.md    development workflow, dependency rules and the release procedure
docs/IMPLEMENTATION.md  build order and the decisions shared across all three
scripts/                release-create.sh builds the artifacts, bazel-create-status.sh
                        the build stamps, bazel/ the container image macro
```

## Building

The build is Bazel with Bzlmod only; Gazelle generates the `BUILD` files. Versions are pinned in
`.bazelversion` and `MODULE.bazel`, and [bazelisk](https://github.com/bazelbuild/bazelisk) picks up
the right Bazel automatically.

```sh
bazel build //...                 # everything
bazel test  //...                 # everything
bazel test  //... --config=race   # with the race detector
bazel run   //:gazelle            # regenerate BUILD files after adding or moving Go files
```

`--config=race` is not the default because rules_go's race instrumentation requires cgo, which the
release configuration deliberately disables. CI runs both.

Two test suites need more than the Bazel sandbox offers, and both skip themselves rather than fail
when it is missing:

```sh
# pivot's store, against a real Valkey. CI runs one as a service container.
docker run --rm -d -p 6379:6379 valkey/valkey:9-alpine
bazel test //... --config=race

# The end-to-end tests: the real binaries, a Valkey from testcontainers, and a
# backend. Outside Bazel, because they need a Docker socket and a Go toolchain.
go test -tags e2e -timeout 10m ./tests/e2e/...
```

Release artifacts are built through the same script semantic-release uses, so the path is exercised
on every pull request:

```sh
scripts/release-create.sh --version 0.2.0              # the whole set, under dist/
scripts/release-create.sh --version 0.2.0 --dry-run    # build everything, write nothing
scripts/release-create.sh --targets linux/amd64        # one target, stamped from git
```

Static, stripped, cgo-free, for `linux/{amd64,arm64}` and `darwin/{amd64,arm64}`: one tarball per
service per target, one combined tarball per target, and a checksum file covering all of them. The
script needs [libsh](https://github.com/adnoctem/libsh) on the machine — see
[`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md).

No service uses cgo, and no C toolchain is registered for first-party code.

## Developing

```sh
pre-commit install
pre-commit run --all-files
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/) with the project as the
scope — `feat(protean): …`, `fix(pkg/kv): …` — because semantic-release derives the version from
them.

[`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) is the full development workflow: the task table, the
gotchas worth knowing before the first `bazel test`, the dependency rules, and how a release is
made. [`AGENTS.md`](AGENTS.md) is the same ground condensed for an agent working in this repository,
and [`docs/ACKNOWLEDGEMENTS.md`](docs/ACKNOWLEDGEMENTS.md) records where the conventions, formats
and test vectors came from.

## Releasing

Releasing is manual and gated. The Release workflow does nothing unless `NETORY_RELEASE_ENABLED` is
`true` in the repository's Actions variables and somebody dispatches it; Testing dispatches it after
a successful run on `main` or `next`, passing the commit it tested, and Release refuses to continue
if the branch has advanced since. A release publishes the tarballs and checksums as GitHub release
assets and the three images to GHCR, all stamped with the same version.

netory is in 0.x: a breaking change takes the minor version, and the release script refuses
anything that is not a plain `0.x.y`. The first release is a one-off `bootstrap` dispatch, because
semantic-release with no tag to measure from would propose 1.0.0.
[`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) has the procedure, including what to do when a
release stops halfway.

## Secrets

Each service takes exactly one high-entropy secret — `PROTEAN_SECRET`, `SIGNPOST_SECRET`,
`PIVOT_SECRET` — delivered however the operator prefers: environment variable, file, systemd
credential, container secret. Every key in use is derived from it with HKDF under a
purpose-specific label, and the raw secret is never handed to a consumer.

protean and signpost rely on Badger's encryption at rest for what they store. Valkey has no
equivalent, so pivot encrypts credentials itself before writing them, through
[`pkg/seal`](pkg/seal/seal.go) — and because its state is shared, **every pivot replica must be
given the same secret**.

Generate one with `<service> secret generate`. A secret shorter than 32 bytes after decoding is
rejected; see [`pkg/secret`](pkg/secret/secret.go) for why that requirement is what makes the
cheaper derivation safe.

## Licence

MIT. See [LICENSE](LICENSE).
