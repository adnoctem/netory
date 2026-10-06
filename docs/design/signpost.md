---
type: design-document
status: draft
project: netory
created: 2026-10-05
tags:
  - design-doc
  - golang
  - netory
  - distribution
  - badger
---

# Design Document: signpost (Public Script Router)

## 1. Overview

`signpost` is a public script router in the `netory` monorepo. It takes a bundle of scripts plus one manifest and serves each script at a configured URL path.
The typical use is the one-line install pattern — `curl -fsSL https://example.org/install.sh | sh` or `irm https://example.org/install.ps1 | iex`.

The design constraint that drives everything else: **the served bytes are executed verbatim by the client, unreviewed.** A user who pipes a URL into a shell has
delegated their trust entirely to the integrity of the response. Every other decision in this document — immutable releases, atomic alias swaps, extraction
hardening, truncation protection — follows from that single fact.

**In scope:**

- Bundles as `.zip` or `.tar.gz` with one `.yaml` or `.json` manifest.
- Immutable, versioned releases with movable aliases and rollback.
- Anonymous public read access over HTTPS.
- Publishing and administration through a Cobra CLI over a Unix domain socket.
- The shared event manager with SMTP and HTTP webhook notifications.

**Out of scope:** authenticated downloads, remote publishing APIs, script execution on the server, Windows as a supported server platform.

> [!INFO] Related
> Shares the `netory` monorepo, the Bazel build setup, and the `pkg/` packages (kv, secret, admin, event, notify, log, stamp) with [[protean]] and [[pivot]].
> The layout follows the `gopskit` conventions.

---

## 2. Core Architecture & Principles

- **Immutable Releases, Movable Aliases:** a published release is never modified. Publishing and rollback are atomic alias swaps, which is what guarantees a
  client never observes a half-published state.
- **All-or-Nothing Validation:** a bundle that fails any validation step is rejected whole. Nothing is partially published, so there is no state in which some
  routes are new and others are stale.
- **One Binary, One Database Owner:** `signpost server start` runs the server, which is the only process that opens Badger. Every other subcommand is a
  short-lived client.
- **Local-Only Publishing:** there is no network publishing API. Publishing from CI or another machine goes through SSH or `docker exec` and then the local CLI,
  so the publish path has no remotely reachable attack surface.
- **Integrity Is the Product:** checksums per route, `ETag` from the content hash, HTTPS only, and optional signature verification. The server serves code; the
  guarantee it sells is that the code is the code that was published.
- **Never Execute, Only Serve:** signpost does not run the scripts it distributes. Scripts are opaque payloads, validated structurally and served unchanged.
- **Secrets Derived, Never Used Raw:** one high-entropy `SIGNPOST_SECRET` enters the process; every key in use is derived from it via HKDF with a
  purpose-specific info label.
- **Nothing Lost on Restart:** events are persisted before delivery is attempted, using the same outbox as [[protean]].

---

## 3. Repository, Build & Process Architecture

signpost lives in the `netory` monorepo next to [[protean]] and shares its build setup and `pkg/` packages (kv, secret, admin, event, notify, log, stamp). Bazel
with Bzlmod and Gazelle, `gopskit` layout, no cgo, MIT licence. Application code sits in `internal/signpost/{app,cmd,config,server,bundle}`. The toolchain is
pinned at Bazel 9.2.0, rules_go 0.64.1, Gazelle 0.54.0 and the Go 1.26.8 SDK — verified in Phase 0, see [[protean]] §10.1.

The forwarded-header parsing that §9.6 depends on lives in `pkg/forwarded`, shared with [[protean]] and [[pivot]] rather than copied into each. Reading
`X-Forwarded-For` correctly is a small piece of code with a well-known way of being wrong, and the consequences differ per service but are serious in all of
them — protean writes the resolved address into DNS, signpost refuses to serve unless it can confirm the hop was encrypted. A second copy would drift, and the
drift would be invisible until someone spoofed an address.

One binary serves both roles. `signpost server start` runs the server, which is the only process that opens the Badger database. It exposes two listeners:

- **Public API (HTTPS, network-facing):** serves scripts anonymously. Read-only.
- **Admin API (Unix domain socket, local only):** used by the CLI for publishing and configuration. Access is controlled by socket file permissions.

Publishing from CI or another machine goes through SSH or `docker exec`, then the local CLI. There is no network publishing API.

### 3.1 CLI Command Tree

```text
signpost server   start
signpost bundle   publish | validate | list | rollback | remove
signpost alias    set | list | remove
signpost notifier add | list | remove | test
signpost config   get | set | list
signpost secret   generate | rotate
signpost version
```

`bundle validate`, `secret generate`, and `version` work without a running server.

---

## 4. Bundles & Manifest

A bundle is one `.zip` or `.tar.gz` archive containing scripts and exactly one manifest at the archive root. YAML and JSON map onto the same schema, validated
with JSON Schema.

### 4.1 Manifest Schema

```yaml
version: 1 # manifest schema version
release: 1.4.0 # bundle version, unique per signpost instance
routes:
  - path: /install.sh
    file: scripts/install.sh
    content_type: text/x-shellscript
  - path: /install.ps1
    file: scripts/install.ps1
    content_type: text/plain
```

Routes take one further optional field, `skip_truncation_check`, which opts a single route out of the §6.3 check. See §9.5 for why it exists and what is recorded
when it is used.

> [!NOTE] The schema is generated, not maintained
> `docs/schema/signpost-manifest-v1.json` is produced from the Go types that validate the manifest, so it cannot drift from them — a test fails if the committed
> file and the generated one differ. It describes a well-formed manifest only; the checks JSON Schema cannot express stay in Go. See §9.1.

### 4.2 Validation

Validation runs on `bundle validate` locally and again on `bundle publish` in the server:

1. Archive is well-formed and within size and entry-count limits.
2. Exactly one manifest exists and matches the schema.
3. Every route references an existing file; no file is referenced outside the bundle.
4. Paths are unique and do not collide with reserved server paths.
5. Scripts pass the truncation-protection check (see §6.3).

A bundle that fails any step is rejected as a whole; nothing is partially published. Running the same validation in both places is deliberate: the local pass
gives fast feedback, and the server pass is the one that is actually trusted, since the local CLI is outside the server's control.

---

## 5. Releases & Serving

Every published bundle becomes an immutable release; the public routes are served from whichever release the active alias points to. Publishing and rollback are
atomic alias swaps, so clients never see a half-published state.

- **Releases** are never modified after publishing. `bundle remove` deletes a release that no alias references.
- **Aliases** (`latest`, `stable`, custom) point to one release. `bundle rollback` moves the alias back to the previous release.
- **Versioned paths** optionally expose a specific release, e.g. `/v1.4.0/install.sh`, for pinned installs.

### 5.1 Storage

Release metadata lives in Badger; script contents live on the local filesystem behind a storage interface, so an S3 backend can be added later without touching
the serving path.

### 5.2 Response Behaviour

- `Content-Type` from the manifest; `X-Content-Type-Options: nosniff`.
- A SHA-256 checksum per route is published at `<path>.sha256`, in `sha256sum`'s own format so it pipes into `sha256sum -c` unaltered.
- `ETag` from the content hash; short cache lifetimes on alias routes, long ones on versioned routes.
- An explicit `Content-Length` on every response. A client piping into a shell can only detect a truncated download if it was told how much to expect, which
  makes this the transport-level half of §6.3.
- `X-Signpost-Release` naming the release served, so a report of odd behaviour can name a version rather than a URL.
- Unknown paths return 404 without listing available routes.

The cache split follows from the mutability split: an alias route can change meaning at any publish, so it must not be cached for long. A versioned route is
immutable by construction and can be cached indefinitely.

---

## 6. Security

signpost serves code that users pipe straight into a shell, so the integrity of every served byte is the core security property. Three areas matter.

### 6.1 Extraction Hardening

- Reject entries with absolute paths or `..` segments (zip-slip).
- Reject symlinks and hardlinks in tar archives.
- Enforce limits on compressed size, uncompressed size, and entry count (decompression bombs).
- Extract into a fresh staging directory; move into place only after full validation.

> [!IMPORTANT] Archive extraction is the primary untrusted input path
> Every bundle arrives as an archive that the server must unpack before it can validate anything. That makes the extractor the one component processing
> attacker-shaped input before any other check has run. Staging extraction and promoting only after validation is what keeps a malicious archive from touching
> the live tree at all.

### 6.2 Integrity

- HTTPS only; plain HTTP requests are not served scripts.
- Published SHA-256 checksums per route, so cautious users can verify before executing.
- Optional bundle signature verification on publish. Tooling (cosign, minisign, or stdlib `crypto/ed25519`) is an open decision.
- PowerShell scripts can be Authenticode-signed before bundling so they run without lowering `ExecutionPolicy`. signpost serves them unchanged.

### 6.3 Truncation Protection

A connection drop mid-download can execute half a script. signpost rejects shell scripts whose logic is not wrapped in a function that is only called on the last
line:

```sh
main() {
    # install logic
}
main "$@"
```

The equivalent check for PowerShell — a script block or function invoked at the end — is applied to `.ps1` files.

> [!CAUTION] This check is structural, not semantic
> It verifies that the script _can_ only act once fully received. It cannot verify that the script is safe, correct, or that its logic is genuinely confined to
> the wrapper. A script that passes the check can still do anything it likes once invoked.

---

## 7. Secrets, Events & Notifications

signpost uses the same secret handling and notification stack as [[protean]], from the shared `pkg/secret`, `pkg/event`, and `pkg/notify` packages.

### 7.1 `SIGNPOST_SECRET`

- One high-entropy string, minimum 32 bytes, delivered by any means. `signpost secret generate` produces a valid one.
- Keys derived with `crypto/hkdf` and SHA-256, one info label per purpose (`signpost/kv-encryption`, `signpost/webhook-signing`).
- The Badger database is encrypted with the derived 32-byte key. It holds release metadata, aliases, notifier credentials, and the outbox.
- `secret rotate` re-keys the database with the server stopped.

### 7.2 Events

| Event              | Trigger                          |
| ------------------ | -------------------------------- |
| `bundle.published` | New release created              |
| `bundle.rejected`  | Validation failed on publish     |
| `alias.changed`    | Alias moved, including rollbacks |
| `bundle.removed`   | Release deleted                  |

### 7.3 Delivery

Delivery uses the persistent outbox with retries, `net/smtp` through the operator's relay, and HMAC-signed HTTP webhooks, exactly as in [[protean]].

Event deduplication is **off by default**, which is the one place signpost's use of the shared stack differs from protean's. `pkg/event` collapses events on type
and subject, which is right for a dynDNS host flapping between two addresses. Every signpost event is a human administrative act arriving over a local socket, so
there is nothing to flap — and the one sequence a window would collapse is publish, notice, roll back: three `alias.changed` events for the same alias, well
inside a minute, of which an operator would hear only the first. Losing the rollback notification is precisely the notification not to lose.
`events.dedup_window` is still available for an operator who wants one.

> [!NOTE] Resolved: `pkg/kv` namespace race
> Fixed once in Phase 0 for all three services. The namespace is a per-call argument, with an immutable `kv.Handle` for binding one; `SetNamespace` no longer
> exists. `pkg/kv/kvtest` is a conformance suite holding the behaviour in place. See [[protean]] §10.1 and §10.4 for the full record, including two Badger
> behaviours that affect signpost directly: an expiring key's TTL is a lower bound at one-second granularity, and `Keys`/`Scan` return entries in
> **unspecified order**, so release and alias listings must sort for themselves rather than relying on Badger's key ordering.

---

## 8. Compliance & Platform Support

Linux is the only supported platform. macOS and Windows are best-effort, untested, and no Windows binaries are shipped.

### 8.1 ISO 27001 Notes

- signpost distributes executable content, so it is a high-risk asset in the change-management sense.
- Every publish, rollback, alias change, and removal is written to an append-only audit log: who, what, when, bundle checksum, and signature status.
- Releases are retained, so any script ever served can be reproduced for an audit.
- Key management for `SIGNPOST_SECRET` maps to A.8.24 Cryptography.

### 8.2 GDPR

Access logs contain client IP addresses. The retention period is configurable; the default is to be defined.

---

## 9. Open Questions & Verification Items

Items keep their original number for the life of the document, so a cross-reference stays valid after an item is resolved. They are headings rather than a
numbered list because Prettier, which is authoritative for Markdown here, renumbers ordered lists.

### 9.1 Finalize the manifest schema — ✅ resolved 2026-10-09

Settled as the shape in §4.1 plus one optional field, `skip_truncation_check`, which §9.5 needed. The manifest is parsed with `gopkg.in/yaml.v3` and validated in
Go; unknown fields are rejected, so a typo in a manifest key fails rather than being ignored.

The JSON Schema is **generated from the Go types** and committed at `docs/schema/signpost-manifest-v1.json`, rather than written beside them. Validation in both
the CLI and the server runs the Go code, so a hand-written schema would be a second description of the same thing and free to drift the moment someone added a
field. Deriving it means the property names, their types and which ones are required come from the structs, and the bounds and patterns come from the same
constants and regexps the validator uses. `bundle.Schema()` produces it and a test fails if the committed file differs, so the file cannot go stale.

The schema describes a well-formed manifest and nothing more. Reserved paths, route-path uniqueness, that every route's file exists in the archive, and the
truncation check are not expressible in JSON Schema or depend on the archive rather than the manifest, which is why the Go validation remains the thing that
decides whether a bundle may be published. No JSON Schema validator is a dependency of either the CLI or the server.

### 9.2 Content negotiation — ✅ resolved 2026-10-09

Separate paths only. There is no User-Agent-driven negotiation and no `Vary` header.

Serving different bytes at one path would break the §6.2 integrity story at its foundation: a published checksum is a statement about one sequence of bytes, and
a path whose content depends on a request header has no single checksum to publish. It would also make the one-line install pattern unverifiable in the way that
matters — `curl … | sha256sum -c` would pass or fail depending on what `curl` happened to send.

A bundle serves `/install.sh` and `/install.ps1`, and the install instructions name the right one.

### 9.3 Verbatim or templated serving — ✅ resolved 2026-10-09

Verbatim. The bytes in the archive are the bytes stored, the bytes hashed, and the bytes served; nothing between the bundle and the client rewrites them.

Templating at publish time would have been defensible — the checksum would still cover what is served, because it would be computed after rendering. It is
refused anyway, because it moves the thing a signature covers. A signature is made over the archive before publishing; if the server rendered the scripts
afterwards, the signature would attest to an input the server then changed, and the one question a signature exists to answer — are these the bytes the author
signed? — would have no honest answer.

A script that needs its own version or base URL carries them as literals set in the bundle, which the §6.3 check permits at the top level, or derives them at
runtime.

### 9.4 Bundle signing tooling — ✅ resolved 2026-10-09

minisign-compatible verification, implemented in `internal/signpost/bundle`. signpost verifies; it never signs, and there is no key material in the database
beyond the trusted public key.

minisign over cosign because cosign brings an OCI-shaped toolchain and a transparency log into a service whose publish path is a local socket, and over bare
`crypto/ed25519` because a bespoke signature format would mean operators could not use a tool that already exists to produce one. A minisign public key is a
single line an operator can paste into `signpost config set publish.signing_key`.

Both algorithms are supported: `Ed`, Ed25519 over the file, and `ED`, Ed25519 over its BLAKE2b-512 hash, which is what the current CLI emits. Both of a
signature's parts are checked, not only the first — the global signature is what binds minisign's trusted comment to the release, and that comment is recorded in
the audit trail under §8.1, so accepting it unchecked would mean recording a field anyone could rewrite.

> [!NOTE] Verified against a genuine signature, not a round trip
> Correctness here is pinned by verifying an actual release signature from minisign's own author, `minisign-0.12.tar.gz.minisig`, committed as test data. A
> signer and a verifier written from the same misunderstanding of the format agree with each other perfectly, so a self-consistent round-trip test would have
> passed with a wrong byte layout. The generated-keypair tests cover what a real fixture cannot — the legacy algorithm, malformed inputs, and the publish path's
> signature policy — but they are not what establishes format compatibility.

This adds one dependency, `golang.org/x/crypto`, for `blake2b`. The standard library has no BLAKE2b and the `ED` algorithm needs it, so the alternative was
hand-rolling a hash or being unable to verify what `minisign -Sm` produces. Signed off 2026-10-09.

Signature verification is optional per instance and enforceable with `publish.require_signature`. When it is required, the signature is checked **before the
archive is unpacked**: the extractor is the component that processes attacker-shaped input (§6.1), so nothing hostile reaches it until the bytes are known to
come from the trusted key. A signature that is supplied but cannot be verified — no configured key, a key mismatch, altered bytes — is an error rather than a
quiet downgrade to "unsigned", because a publisher who attached one would otherwise have no way to tell it had been ignored.

### 9.5 PowerShell truncation-protection check — ✅ resolved 2026-10-09

Defined as the direct analogue of the shell check, and implemented in `internal/signpost/bundle/truncation_ps1.go`.

A `.ps1` file passes when every top-level statement is either prelude or an invocation of a function or script block the file itself defines, and the last
non-empty line is such an invocation. Prelude is `#Requires`, `[CmdletBinding()]` and `param(...)`, `Set-StrictMode`, `$ErrorActionPreference` and other plain
variable assignments to literals, `using` statements, and `function`/`filter`/`class` definitions. An assignment whose value is a subexpression — `$v = $(…)`,
`$v = @(…)`, a pipeline, or a command in backticks — is a command for this check's purposes, exactly as `VERSION=$(curl …)` is in the shell check.

Both checks share their structure: find the definitions, then insist that every top-level statement which can act on the system is a call to one of them, with
the last line being the call. Neither is a parser, and both are deliberately conservative — an unrecognised top-level construct is treated as a command and
refused, because the opposite default would let a real command through.

> [!CAUTION] Both checks are heuristics over syntax
> They verify that a script _can_ only act once fully received. They cannot verify that it is safe or correct, and they will occasionally be wrong about a
> legitimate script. `skip_truncation_check: true` on a route is the recorded escape hatch: `bundle list` reports it, the publish event carries it, the publish
> output warns about it, and `publish.allow_truncation_opt_out false` refuses it outright.

A `.sh` or `.ps1` route whose content cannot be classified as either language at all is refused rather than waved through, so adding a third scripting language
is a deliberate act of adding a check for it.

### 9.6 TLS termination — ✅ resolved 2026-10-06

Decided once for all three services. Both modes are supported and selected by configuration: native TLS from operator-supplied certificate and key files, or
plain HTTP behind a reverse proxy with an explicit `trusted_proxies` list. ACME is **not** implemented. See [[protean]] §4.1 for the mechanics and §10.5 for the
decision record.

signpost serves anonymously, so it has no per-source rate limiter depending on the client address the way [[protean]] does. `trusted_proxies` still governs what
lands in the access log, which is the GDPR-relevant artefact in §9.7 — an unconfigured proxy deployment logs the proxy's address for every request, which is
useless rather than merely wrong.

> [!IMPORTANT] HTTPS-only is a property signpost must enforce, not merely prefer
> §6.2 requires that plain HTTP requests are not served scripts. In native-TLS mode that is automatic. In reverse-proxy mode signpost receives plain HTTP by
> design and cannot tell a proxied HTTPS request from a direct plain one by the connection alone, so it has to trust `X-Forwarded-Proto` from a trusted proxy
> and refuse to serve when the header says `http` or is absent. The client is about to pipe the response into a shell; downgrading that silently is the one
> failure mode this service exists to prevent.

### 9.7 Access-log retention default — ✅ resolved 2026-10-09, as a different setting

Resolved by replacing the question rather than answering it. There is no retention setting, because signpost cannot enforce one: the access log is written to the
structured log and leaves the process immediately, after which its lifetime belongs to the operator's log pipeline. A configurable period signpost had no way to
apply would have been a promise it could not keep, which is worse than no promise.

What signpost does own is how much personal data enters the record in the first place, so that is the setting: `accesslog.client_address`, one of `full`,
`anonymised` or `off`, defaulting to **`anonymised`** — IPv4 truncated to a `/24`, IPv6 to a `/48`. That is data minimisation under GDPR Art. 5(1)(c) rather than
a storage-limitation claim under Art. 5(1)(e), and it is the stronger of the two here because it is the one signpost can actually implement.

The reduction happens where the record is built, before it reaches any log handler: a record that has left that function carrying a full address cannot be
un-sent. `full` is available for an operator investigating abuse, who then owns that decision; the startup log says so at warn when it is set. An unrecognised
stored value is treated as `off` rather than `full`, so a settings document written by a future version cannot make this build record more than it knows it
agreed to.

Every client-controlled field in the record — the path, the User-Agent — is bounded and stripped of control characters before it is written, because a log line a
client can inject a newline into is a log line a client can forge.

### 9.8 The `pkg/kv` namespace race — ✅ resolved in Phase 0

Shared with [[protean]] and [[pivot]], and resolved once for all three. See the note in §7.3 and [[protean]] §10.4 for the full record.

Two consequences land on signpost specifically. `Keys` and `Scan` are documented as returning entries in **unspecified order**, so release listings and rollback
ordering must not rely on Badger's key ordering — the Valkey implementation gives no such guarantee and a caller depending on it would break. And `kv.SetIfAbsent`
is the primitive that makes "release version unique per signpost instance" (§4.1) enforceable under concurrency rather than best-effort, while
`kv.CompareAndSwap` is the one behind an atomic alias swap that only moves an alias still pointing where the publisher expects.
