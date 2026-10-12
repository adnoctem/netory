# netory — Implementation Brief

This file is the _orchestration_ layer: build order, cross-project decisions, and where to source
tooling. The per-project design documents in `docs/design/` are the **source of truth for scope,
architecture and decisions**. Where this file and a design document disagree about _what a service
does_, the design document wins. Where they disagree about _build order or shared packages_, this
file wins, because it is the only document that sees all three projects at once.

## 1. Scope

Three Go services, one Bazel/Bzlmod monorepo, MIT licence, no cgo:

| Order | Project    | Design doc                | One-liner                                | State store |
| ----- | ---------- | ------------------------- | ---------------------------------------- | ----------- |
| 1     | `protean`  | `docs/design/protean.md`  | Self-hosted dynDNS control plane         | Badger      |
| 2     | `signpost` | `docs/design/signpost.md` | Public script router (`curl … \| sh`)    | Badger      |
| 3     | `pivot`    | `docs/design/pivot.md`    | Transparent API proxy (Shopware 6 first) | Valkey      |

Implement them **one after another**, in that order. Do not start the next project before the
previous one builds, tests, and is documented.

Why this order: protean and signpost are single-replica, Badger-backed, and share the admin-socket
and event/notify machinery — building protean first establishes the whole `pkg/` foundation, and
signpost then reuses it almost unchanged. pivot comes last because it is the only multi-replica
service and the only one needing the Valkey store implementation.

## 2. Repository layout

`gopskit` layout, as all three design documents specify:

```text
netory/
├── MODULE.bazel, go.mod, BUILD.bazel, .bazelrc, .bazelversion
├── cmd/{protean,signpost,pivot}/main.go     # thin entrypoints only
├── internal/
│   ├── protean/{app,cmd,config,server,provider}
│   ├── signpost/{app,cmd,config,server,bundle}
│   └── pivot/{app,cmd,config,server,rules,auth,cache}
├── pkg/                                     # shared across all three
│   ├── kv/      # store interface + Badger and Valkey implementations
│   ├── secret/  # APP_SECRET validation + HKDF derivation
│   ├── admin/   # Unix-domain-socket client/server plumbing
│   ├── event/   # event bus + outbox
│   ├── notify/  # Notifier interface, SMTP, webhook
│   ├── log/
│   └── stamp/
└── docs/
    ├── IMPLEMENTATION.md    # this file
    └── design/{protean,signpost,pivot}.md
```

Go module path: `github.com/adnoctem/netory`. Gazelle prefix and `go_naming_convention
import_alias` as in `gopskit/BUILD.bazel`.

## 3. Phase 0 — harness before features

Do this once, before any `protean` application code:

1. `MODULE.bazel` with Bzlmod + Gazelle, `go_deps.from_file(go_mod = "//:go.mod")`.
   Copy the shape from `~/Software/Code/AdNoctem/gopskit/MODULE.bazel`, including the Badger
   override — it is required, not optional:

   ```python
   go_deps.gazelle_override(
       directives = ["gazelle:proto disable_global"],
       path = "github.com/dgraph-io/badger/v4",
   )
   ```

2. **Resolve the Bazel 9 LTS question first** (`docs/design/protean.md` §3, flagged as a
   verification item). Check `rules_go` and Gazelle compatibility with Bazel 9.x _before_ pinning
   `.bazelversion`. If Bazel 9 is not supported by the current `rules_go`/Gazelle, pin the newest
   version pair that is, and record the finding and the chosen versions in
   `docs/design/protean.md` §10. Discovering this after the build graph exists is expensive.
3. Source dev/commit/CI tooling from `~/Software/Code/AdNoctem/gopskit`, adapted — not symlinked,
   and not copied blindly:
   - `.pre-commit-config.yaml` — drop the Helm-chart exclusions (no charts here), keep the
     `require_serial: true` comment on the prettier hook.
   - `.github/linters/*` — markdownlint, typos, gitleaks, zizmor, shellcheck configs.
   - `.github/workflows/{testing,superlint,release,stale}.yaml` — retarget to this module;
     `release.yaml` and `.releaserc` drive semantic-release.
   - `.golangci.yml`, `renovate.json`, `.gitignore`, `scripts/bazel-create-status.sh` (used by
     `build --workspace_status_command` in `.bazelrc`).
   - `LICENSE` (MIT), `.github/{AUTHORS,CODEOWNERS}`.
4. CI must at minimum run: `bazel build //...`, `bazel test //...`, `go vet`, `golangci-lint`,
   `govulncheck`, and a `linux/amd64` build. Windows is explicitly **not** a supported server
   platform for any of the three services.
5. Commit messages follow Conventional Commits (semantic-release is wired to them). Use the
   project name as the scope: `feat(protean): …`, `fix(pkg/kv): …`.

**Accept Phase 0:** `bazel build //...` and `bazel test //...` pass on an empty-but-wired tree,
`pre-commit run --all-files` is clean, and CI is green.

## 4. Cross-project decision: `pkg/kv`

All three design documents flag the same blocker, and it must be settled **once, in Phase 0**, not
three times:

- `gopskit`'s `pkg/kv` holds the current namespace as shared mutable state on `*Database`
  (`SetNamespace` + `currentNamespace`). In a concurrent server, `SetNamespace` then `Set` from two
  goroutines can write into the wrong namespace. This is a correctness defect, not a style
  preference — see `docs/design/protean.md` §5.3 and `docs/design/pivot.md` §8.2.
- Port `pkg/kv` into this repo with the namespace as a **per-call argument or a per-namespace
  handle**. `SetNamespace` does not survive the port.
- Define `pkg/kv` as an **interface up front**, with the Badger implementation landing in Phase 0
  (for protean and signpost) and the Valkey implementation landing when pivot starts. The design
  documents call for sequencing the interface extraction and the race fix together rather than
  doing the same surgery twice; this is that sequencing.
- Add a concurrency test that fails against the old shared-state design (`go test -race`, parallel
  writers to two namespaces).

## 5. Conventions for all three services

These are consistent across the three design documents; they are collected here so you do not have
to re-derive them per project:

- **One binary, one database owner** (protean, signpost): `<app> server start` is the only process
  that opens Badger; every other subcommand is a short-lived admin-socket client. Badger's
  exclusive directory lock enforces this. pivot is the exception — stateless replicas over Valkey.
- **Two listeners per service:** a network-facing HTTPS listener, and an admin API on a Unix domain
  socket (`0600`, dedicated service user, no tokens — file permissions _are_ the authorization).
  There is no remote admin API in any of the three.
- **TLS termination is the operator's choice, and the same choice in all three** (decided 2026-10-06,
  resolving `protean` §10.5, `signpost` §9.6 and `pivot` §10.7). Each service supports native TLS
  from operator-supplied cert and key files, _or_ plain HTTP behind a reverse proxy with an explicit
  `trusted_proxies` list. ACME is not implemented. `X-Forwarded-For` and `X-Forwarded-Proto` are
  honoured **only** from a peer inside `trusted_proxies`, which has no default — see
  `docs/design/protean.md` §4.1.
- **CLI:** Cobra, Git-style noun → verb (`protean host add`, `signpost bundle publish`,
  `pivot rules test`). Exact trees are in each design doc's §3.1/§4.1. `secret generate` and
  `version` must always work without a running server.
- **Secrets:** one high-entropy `<APP>_SECRET` (`PROTEAN_SECRET`, `SIGNPOST_SECRET`,
  `PIVOT_SECRET`), rejected below 32 bytes after decoding. Every working key is derived via
  `crypto/hkdf` (stdlib, Go 1.24+) + SHA-256 with a purpose-specific info label
  (e.g. `protean/kv-encryption`). The raw secret is never handed to a consumer, and never used
  directly as the Badger encryption key (Badger takes 16/24/32 bytes; derive 32).
- **Deny by default** wherever a policy decision exists — most sharply in pivot's path rules, where
  deny is evaluated before allow and an unmatched request is denied.
- **No cgo, no runtime plugin loading.** Providers and notifiers are compiled in and registered at
  `init`. Adding one is a code change and a rebuild.
- **Standard library first.** An external dependency needs a reason the stdlib cannot cover. Ask
  before adding a dependency not named in the relevant design document.
- **Errors** wrap with `%w` and are returned, not panicked on. User-facing messages carry a hint.
- **Third-party libraries sit behind interfaces this repo owns** — never in place of them. That
  applies to the DNS provider interface (libdns is an _adapter_, per
  `docs/design/protean.md` §7.1), the notifier interface, and the kv store.

## 6. Working agreement

- Each project ends with working, tested, and documented software before the next one begins.
- Every design document closes with a **§10 "Open Questions & Verification Items"**. Work through
  them as you reach the relevant code. **When you resolve one, update the design document in the
  same change** — the doc is living, not a snapshot.
- **If something is ambiguous or missing, ask. Do not assume.** This is explicit in the design
  documents and it applies to all three.
- `[[name]]` inside the design documents is an Obsidian wiki-link; it refers to
  `docs/design/name.md` in this repo. `[[carto]]` refers to the `carto` tool in the `gopskit`
  repository at `~/Software/Code/AdNoctem/gopskit` — read it for conventions, do not vendor it.
- Repository documentation is written separately, per project, as that project lands. Do not
  duplicate the design documents into it.
- **The user-facing document for a service is `cmd/<service>/README.md`**, beside its entrypoint:
  how to run it, configure it, operate it and deploy it. The design document says why the service is
  the way it is; the README says how to use it. The root `README.md` is the overview and the
  one-line install, for a user; everything a contributor or maintainer needs is in
  `docs/CONTRIBUTING.md`.
