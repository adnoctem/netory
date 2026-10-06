---
type: design-document
status: draft
project: netory
created: 2026-10-05
tags:
  - design-doc
  - golang
  - netory
  - dyndns
  - badger
---

# Design Document: protean (Self-Hosted dynDNS Control Plane)

## 1. Overview

`protean` is a self-hosted dynDNS control plane in the `netory` monorepo. It accepts address updates from dynDNS clients and writes them to an existing DNS
provider. It does not host DNS zones itself and is not an authoritative name server.

The design constraint that drives everything else: **protean owns no DNS data.** It is a translation layer between authenticated update requests and a provider
API. Every record it touches lives in Cloudflare, Route53, or Spaceship, and the provider remains the source of truth.

**In scope:**

- A DynDNS2-compatible update endpoint, so existing clients (ddclient, inadyn, FRITZ!Box custom provider) work unchanged.
- Per-host authentication tokens.
- Compiled-in DNS provider integrations: Cloudflare, Route53, Spaceship.
- An internal event manager with SMTP and HTTP webhook notifications.
- A Cobra CLI for local administration over a Unix domain socket.

**Out of scope:** authoritative DNS, remote management, runtime-loaded plugins, Windows as a supported platform.

> [!INFO] Related
> Shares the `netory` monorepo, the Bazel build setup, and the `pkg/` packages with [[signpost]] and [[pivot]]. The layout follows the `gopskit` conventions.

---

## 2. Core Architecture & Principles

- **One Binary, One Database Owner:** `protean server start` runs the long-lived server; every other subcommand is a short-lived client of it. The server is the
  only process that opens Badger, which holds an exclusive directory lock and enforces this at the filesystem level.
- **Local-Only Administration:** the admin surface is a Unix domain socket, not a network API. Remote administration goes through SSH or `docker exec` and then
  the local CLI. There is nothing to authenticate against remotely because there is nothing listening remotely.
- **Protocol Compatibility Over Novelty:** the update endpoint speaks DynDNS2 because every relevant client already does. A better protocol that requires
  replacing router firmware is worse than an old protocol that works today.
- **Compiled In, Not Loaded:** providers and notifiers are compiled into the binary and registered at init. No runtime plugin loading, no cgo, no dynamic
  linking. Adding a provider is a code change and a rebuild.
- **Narrow Interfaces, Owned by protean:** the provider interface covers A, AAAA, and TXT records for single names and nothing more. Third-party libraries sit
  _behind_ protean's own interfaces, never in place of them.
- **Standard Library First:** external dependencies need a reason the stdlib cannot cover.
- **Secrets Derived, Never Used Raw:** one high-entropy `PROTEAN_SECRET` enters the process; every key in use is derived from it via HKDF with a purpose-specific
  info label. The raw secret is never passed to a consumer.
- **Nothing Lost on Restart:** events are persisted before delivery is attempted. A process restart or a relay outage delays notifications; it does not drop
  them.

---

## 3. Repository & Build Harness

```text
netory/
├── MODULE.bazel
├── go.mod
├── cmd/
│   ├── protean/main.go        # thin entrypoint
│   └── signpost/main.go
├── internal/
│   └── protean/
│       ├── app/                # application state
│       ├── cmd/                # Cobra commands, CLIOpt registration
│       ├── config/
│       ├── server/             # update API + admin UDS server
│       └── provider/           # compiled-in DNS providers
└── pkg/                        # shared with signpost
    ├── kv/                     # Badger store
    ├── secret/                 # APP_SECRET validation + HKDF
    ├── admin/                  # UDS client/server plumbing
    ├── event/                  # event bus + outbox
    ├── notify/                 # Notifier interface, SMTP, webhook
    ├── log/
    └── stamp/
```

Build notes:

- Bazel with Bzlmod only, Gazelle for `BUILD` file generation. The layout follows `gopskit`. Licence is MIT.
- Go dependencies come from `go.mod` through Gazelle's `go_deps` extension.
- Badger needs the `gazelle:proto disable_global` override, as in `gopskit`.
- cgo is not used and no C toolchain is registered.

> [!NOTE] Resolved: Bazel 9 LTS is supported
> Verified before the build graph was created, on 2026-10-06. The pinned set is **Bazel 9.2.0** (`.bazelversion`), **rules_go 0.64.1** and **Gazelle 0.54.0**
> (`MODULE.bazel`), on the **Go 1.26.8** SDK. No downgrade was needed. See §10.1 for what was exercised.

---

## 4. Process Architecture

One binary serves both roles. The server exposes two listeners with deliberately different exposure and authentication models:

- **Update API (HTTPS, network-facing):** the DynDNS2 endpoint. Requires a per-host token on every request.
- **Admin API (Unix domain socket, local only):** used by the CLI. Access is controlled by socket file permissions (`0600`, dedicated service user). No tokens.

The CLI never opens Badger directly. Since Badger holds an exclusive directory lock, a second process cannot open the database while the server runs — the
constraint is enforced, not merely documented.

### 4.1 CLI Command Tree

Commands follow Git-style noun → verb ordering:

```text
protean server   start
protean host     add | list | remove
protean token    create | list | revoke | rotate
protean provider add | list | remove | test
protean notifier add | list | remove | test
protean config   view | get | set | list
protean backup   create | list | verify | restore
protean outbox   status
protean secret   generate | rotate
protean version
```

`secret generate` and `version` work without a running server. `secret rotate` requires the server to be stopped, and `backup restore` does too - see §5.4. All other commands talk to the admin
socket.

Three commands were added after the first implementation and are recorded here rather than left
undocumented:

- `config view` renders the bootstrap configuration and the runtime settings together. "What is this
  server actually doing" is one question, and answering it should not require running `config get`
  once per key - nor knowing that the listen address and the TLS mode are not settings at all, so
  `config get` would never have shown them.
- `backup create | list | verify | restore` is §5.4.
- `outbox status` exposes the notification outbox. It is the mechanism behind "nothing lost on
  restart", and without a way to look at it the only way to find a notification that never arrived
  is to read the log.

---

## 5. Storage & Secrets

All state lives in an encrypted Badger database owned by the server, keyed from a single `PROTEAN_SECRET`. It holds hosts, token hashes, provider credentials,
notifier credentials, settings, and the notification outbox.

### 5.1 `PROTEAN_SECRET`

The secret works like Symfony's `APP_SECRET`: one string delivered by any means — environment variable, file, systemd credentials, container secret.

- It must be high-entropy. protean rejects secrets shorter than 32 bytes after decoding.
- `protean secret generate` produces a valid secret from `crypto/rand`.
- Keys are derived with `crypto/hkdf` (stdlib since Go 1.24) and SHA-256. Each purpose gets its own info label, e.g. `protean/kv-encryption` and
  `protean/webhook-signing`.
- The Badger encryption key is derived at 32 bytes (AES-256). Badger accepts only 16, 24, or 32 bytes, so the raw secret is never passed directly.

> [!NOTE] Why HKDF and not PBKDF2
> Because the secret is required to be random, HKDF is sufficient. `crypto/pbkdf2` would only be needed for human-chosen secrets, which protean does not accept.
> The rejection of short secrets is what makes the cheaper derivation defensible.

### 5.2 Rotation

`protean secret rotate` re-keys the database with the server stopped. The exact mechanism — Badger key registry rotation — is to be verified during
implementation.

### 5.3 Reuse of `gopskit` `pkg/kv`

> [!NOTE] Resolved: the namespace is now an argument
> `pkg/kv` was ported in Phase 0 with the namespace as a per-call argument, plus an immutable `kv.Handle` for the ergonomics `SetNamespace` used to provide.
> `SetNamespace` did not survive the port, and neither did the global mutex that existed to protect it. See §10.4 for the full list of what changed and the
> conformance suite that holds it in place.

### 5.4 Backups

`protean backup create | list | verify | restore` stores backups on the local filesystem or in S3.
Local covers air-gapped operation and a copy kept beside the service; S3 covers off-host retention.
Added after the first implementation, so it is recorded here rather than left out of the document.

> [!CAUTION] A Badger backup of an encrypted database is plaintext
> Badger's own backup reads key-value pairs through the normal transaction path, which decrypts
> them. A backup of this encrypted database is therefore a plaintext stream of every host, token
> hash, provider credential and notifier password in it, and writing one to a filesystem or a bucket
> would undo §5.1's encryption silently.
>
> `pkg/kv/badgerkv` carries a test that writes a canary credential, takes a backup and asserts the
> canary is in the backup bytes - so the hazard is pinned rather than described, and nobody later
> concludes the sealing is redundant.

Every backup is therefore sealed with AES-256-GCM under a key derived from `PROTEAN_SECRET` at its
own HKDF label, `netory/backup-encryption`. The label is distinct from `protean/kv-encryption`, so a
recovered backup key does not open the live database and vice versa. The nonce is random per backup,
because two backups of the same database are near-identical plaintexts and a reused nonce would leak
their difference.

The consequence: **a backup is only restorable with the secret that made it.** That is the same
property the database already has, so it adds no new way to lose data - but the secret has to be
backed up somewhere other than beside the backups, and the documentation says so.

Sealing is a single AES-GCM operation over the whole backup, so the backup is held in memory and
bounded at 1 GiB. Chunked framing would remove the limit at the cost of a bespoke format to get
wrong, and what protean stores is kilobytes to low megabytes; the error names the outbox, which is
the only thing that could plausibly grow.

**`create`, `list` and `verify` go through the admin socket, so the server does the work.** For S3
that is the point: the server is the process that already holds an instance or task role, and a
plaintext snapshot of every credential has no business crossing a socket when it need not. S3
credentials come from the AWS credential chain rather than from anything protean stores, so backing
up the database does not add a credential to protect.

**`restore` is offline.** Badger holds an exclusive directory lock, so the server must be stopped -
and it should be, because Badger's load _merges_ rather than replaces: keys in the backup overwrite
their counterparts and keys absent from it survive, which would leave a database that is neither the
backup nor what was there before. `restore` refuses a non-empty database unless forced, and a test
pins the merge behaviour so the refusal has a documented reason.

`verify` decrypts a stored backup without restoring it, and exits non-zero on failure so it can run
as a monitoring check. A backup nobody has ever opened is a backup nobody knows works.

---

## 6. Authentication & Update API

Every request to the update API authenticates with a token scoped to exactly one host. The endpoint speaks the DynDNS2 protocol, so existing clients need no
changes.

### 6.1 Tokens

- Generated as 32 random bytes from `crypto/rand`, shown once at `token create`, never retrievable afterwards.
- Stored as a SHA-256 hash, and looked up by that hash - so the presented value is never compared against a stored secret. `crypto/subtle.ConstantTimeCompare`
  guards the second step, confirming the token's host matches a hostname the request claimed, because a timing difference there would let someone holding one
  valid token discover other configured hostnames.
- One token belongs to one host. A host can have several tokens, which is what makes rotation possible without downtime.
- `token revoke` takes effect immediately; `token rotate` issues a new token and revokes the old one.

Slow password hashes (Argon2, bcrypt) are unnecessary here: the tokens are full-entropy random values, not human-chosen secrets, so there is no dictionary
search to slow down.

### 6.2 DynDNS2 Endpoint

`GET /nic/update` (and `POST`) with HTTP Basic auth, password = token. TLS is mandatory, because Basic auth sends the token in every request.

| Parameter  | Meaning                                                                                      |
| ---------- | -------------------------------------------------------------------------------------------- |
| `hostname` | FQDN to update. Optional; must match the token's host when given                             |
| `myip`     | IPv4 or IPv6 address. Falls back to the request source address only when no address is given |
| `myipv6`   | IPv6 address, for clients that send both families separately                                 |

Responses use the DynDNS2 return codes (`good`, `nochg`, `badauth`, `nohost`, `notfqdn`, `abuse`, `dnserr`, `911`). protean also sets a matching HTTP status,
so failures are visible in a reverse proxy's access log without parsing bodies; clients read the body and are unaffected.

> [!NOTE] Corrected 2026-10-09: the username is not the hostname
> This document originally specified "username = hostname", which DynDNS2 conventionally implies and which ddclient and inadyn do send. It is wrong as a
> _requirement_, and checking a FRITZ!Box 7690 is what surfaced it.
>
> A FRITZ!Box has separate Username, Password and "Domain name" fields and authenticates with HTTP Basic from the first two, so the username it sends is
> whatever the operator typed. Requiring username == hostname means typing a full hostname into a field labelled "Username" and otherwise getting `badauth`
> with no explanation. Some clients send no hostname at all, because the credential identifies the host at the provider's end.
>
> So the **token** authenticates, and it already identifies the host: a token belongs to exactly one host (§6.1). A hostname may be asserted through the
> `hostname` parameter or through the username, and is checked against the token's host when it is; a username that is not a well-formed hostname is treated as
> a username and not as a claim. All three client shapes therefore work unchanged.
>
> This does not weaken scoping. The token is the only secret and can only ever update its own host; a hostname is a public DNS name, so requiring it to be
> presented correctly was never a second factor - it only ever turned a correct credential into an unexplained failure. A token presented against a different
> hostname is still refused, now with `nohost` rather than `badauth`, which is what those codes actually mean: the credential is real, the scope is wrong.

> [!CAUTION] Credentials in the query string are refused
> A FRITZ!Box will substitute `<username>` and `<pass>` into any part of the update URL, and several provider guides tell operators to put them in the query
> string. protean refuses that: a token in a URL appears in every access log and proxy log it passes through, which is the same exposure §6.2's TLS requirement
> exists to prevent. The refusal is recognised specifically so the log can say what to do instead, rather than returning an unexplained `badauth`.

### 6.3 IPv6 and DS-Lite

Many German connections use DS-Lite, so the IPv4 address protean observes is frequently a carrier-grade NAT address belonging to the ISP rather than the
subscriber. IPv6 is therefore first-class: AAAA records are updated independently, and the explicit `myip`/`myipv6` parameters take precedence over the request
source address.

### 6.4 Abuse Protection

- Rate limiting per host and per source address.
- `nochg` responses do not trigger provider calls — an unchanged address costs nothing downstream.
- The source address is taken from `X-Forwarded-For` only when the request comes from a configured trusted proxy.

---

## 7. DNS Provider Interface

Providers are compiled into the binary and sit behind one protean-owned interface. Adding a provider means implementing that interface and registering it; there
is no runtime plugin loading and no cgo.

```go
type Record struct {
    Name  string        // relative to zone
    Type  string        // A, AAAA, TXT
    Value string
    TTL   time.Duration
}

type Provider interface {
    Name() string
    Get(ctx context.Context, zone, name string) ([]Record, error)
    Upsert(ctx context.Context, zone string, records []Record) error
    Delete(ctx context.Context, zone string, records []Record) error
}
```

The interface is deliberately narrow: protean manages A, AAAA, and TXT records for single names, and nothing else. Providers register through a
`database/sql`-style registry, with one registration line per provider in `internal/protean/provider`.

### 7.1 libdns as an Adapter

[libdns](https://github.com/libdns/libdns) may be used as an adapter _behind_ the interface, never as the interface itself. That isolates protean from libdns API
changes and keeps the option of hand-written providers open.

### 7.2 Initial Providers

| Provider   | Credentials      | Status                                                          |
| ---------- | ---------------- | --------------------------------------------------------------- |
| Cloudflare | Scoped API token | libdns provider available                                       |
| Route53    | IAM credentials  | libdns provider available                                       |
| Spaceship  | API key + secret | Several competing libdns implementations; evaluate or write own |

> [!NOTE] Resolved 2026-10-07: which providers use libdns
> Cloudflare and Route 53 go through libdns adapters; Spaceship is native. One shared adapter does
> the Record translation, so each libdns-backed file is nothing but credential handling, and
> `provider.Provider` remains the contract - the adapter depends on the three libdns methods protean
> calls, not on libdns's own interfaces, so a release that changes anything else cannot reach
> protean. See §10.2.
>
> Route 53 brings `aws-sdk-go-v2` with it, which dominates build time even though only that one
> provider uses it. That was the accepted cost of not hand-rolling SigV4 request signing.

Spaceship's API is separate from Namecheap's. Domains hosted at Namecheap itself would need a separate provider.

Least-privilege credentials — zone-scoped Cloudflare tokens, IAM policies restricted to the hosted zone — are the operator's responsibility and are
documented as such.

---

## 8. Events & Notifications

protean emits typed events onto an in-process event bus; notifiers subscribe and deliver them over SMTP or HTTP webhooks. The bus, outbox, and notifiers live in
the shared `pkg/event` and `pkg/notify`, so [[signpost]] uses the same implementation.

### 8.1 Events

| Event                             | Trigger                                         |
| --------------------------------- | ----------------------------------------------- |
| `host.updated`                    | Address change written to the provider          |
| `host.update_failed`              | Provider call failed after retries              |
| `auth.failed`                     | Repeated `badauth` for a host or source address |
| `token.created` / `token.revoked` | Token lifecycle via the CLI                     |
| `provider.failed`                 | Provider unreachable or credentials rejected    |

### 8.2 Delivery

- **Outbox:** events are persisted in Badger before delivery and retried with backoff. A restart or relay outage loses nothing.
- **Deduplication and rate limiting:** a flapping connection must not send one mail per IP change.
- **Notifier interface:** `Notify(ctx, Event) error`. New transports implement it and register like DNS providers.

### 8.3 Transports

- **SMTP:** `net/smtp` through the operator's relay. Port 465 uses `tls.Dial` + `smtp.NewClient`; port 587 uses `StartTLS`. CR/LF is stripped from all header
  values built from event data. Subjects are encoded with `mime.QEncoding`.
- **HTTP webhook:** JSON body, signed with HMAC-SHA256 using a key derived from `PROTEAN_SECRET`.

Notifier credentials (SMTP password, webhook endpoints) are stored in the encrypted database. `notifier list` always redacts them.

> [!TIP] Header injection through event data
> Event payloads carry attacker-influenced values — a hostname from a failed auth attempt, for instance. Stripping CR/LF from header values is not a formality;
> it is the control that stops an event field from becoming an extra SMTP header.

---

## 9. Security, Compliance & Platform Support

Linux is the only supported platform. macOS and Windows are best-effort, untested, and no Windows binaries are shipped.

### 9.1 Security Model

| Surface      | Exposure          | Authentication                             |
| ------------ | ----------------- | ------------------------------------------ |
| Update API   | Network, HTTPS    | Per-host token (Basic auth)                |
| Admin API    | Local Unix socket | Socket file permissions                    |
| Database     | Disk              | AES-256, key derived from `PROTEAN_SECRET` |
| DNS provider | Outbound          | Operator-supplied credentials              |

### 9.2 ISO 27001 Notes

- Key management for `PROTEAN_SECRET` — generation, delivery, rotation — maps to A.8.24 Cryptography and should be documented.
- Administrative actions over the socket are written to an audit log: who, what, when.
- All `list` output redacts secrets.

### 9.3 GDPR

IP addresses are personal data. protean ships a configurable retention period for address history and leaves the choice of SMTP relay and webhook receivers to
the operator. Whether a data processing agreement (AVV) is needed depends on that choice and is the operator's decision.

---

## 10. Open Questions & Verification Items

Items keep their original number for the life of the document, so that a reference from [[signpost]] or [[pivot]] stays valid after an item is resolved. They
are headings rather than a numbered list because Prettier — which is authoritative for Markdown here — renumbers ordered lists, and a renumbered item silently
breaks every cross-reference to it.

### 10.1 `rules_go` and Gazelle compatibility with Bazel 9 LTS — ✅ resolved 2026-10-06

Resolved before the build graph existed. Bazel 9 is supported; no downgrade was needed. Pinned: **Bazel 9.2.0**, **rules_go 0.64.1**, **Gazelle 0.54.0**,
**Go SDK 1.26.8**. 9.2.0 is the newest 9.x — 8.8.1 is more recent by date but belongs to the previous LTS line. Gazelle 0.54.0 is the newest _stable_ release;
the registry also lists `1.0.0-beta.1` and `2.0.0-beta.1`, which were skipped.

Verified on a throwaway workspace rather than from release notes: Gazelle `BUILD` generation with `import_alias`; `bazel build //...` with Badger as a
dependency, which confirmed the `gazelle:proto disable_global` override is **still required** and still sufficient with no C toolchain registered; `go_test`
under `--@io_bazel_rules_go//go/config:race`; `--workspace_status_command` stamping through `x_defs`; and a `linux/amd64` cross-build.

Two findings worth recording, because both would otherwise have surfaced much later:

- **`pure` and `race` are mutually exclusive.** `rules_go` fails at analysis time with `race instrumentation can't be enabled when cgo is disabled`. A
  `.bazelrc` that globally forces `//go/config:pure` — the obvious way to express "this repo has no cgo" — silently makes the mandated race test unrunnable.
  `pure` therefore lives in `build:release` only, and the race detector in `test:race`. CI runs both as separate steps.
- **rules_go has no `//go/config:strip` setting.** Stripping a Go binary is `-s -w` through the Go linker, so the release configuration sets
  `--@io_bazel_rules_go//go/config:gc_linkopts=-s,-w`.

`common --enable_bzlmod`, which `gopskit` carries from its Bazel 7 days, was dropped: Bazel 9 removed WORKSPACE entirely, so the flag is accepted but does
nothing.

### 10.2 Spaceship provider — ✅ resolved 2026-10-07, one item left to verify

Written natively against Spaceship's own API rather than through any of the competing third-party libdns packages, whose maturity varies. The surface needed is
three endpoints, so the native implementation is smaller than the dependency would have been. Cloudflare and Route 53 do go through libdns adapters, since
maintained packages exist for both.

The API, confirmed against Spaceship's published documentation rather than assumed: base `https://spaceship.dev/api/v1`, `X-API-Key` and `X-API-Secret`
headers, `GET /dns/records/{domain}` paginated with `take` and `skip`, `PUT` to save and `DELETE` to remove. A and AAAA records carry their address in an
`address` field while TXT carries its text in `value`, and record matching is case-insensitive except for TXT values.

> [!WARNING] Still to verify: the save endpoint's replace semantics
> `PUT /dns/records/{domain}` is documented as _creating_ records, with a `force` flag that disables its conflict-resolution checker. It is not documented to
> replace an existing RRset the way libdns's SetRecords does, and an address update must replace rather than append - two A records for one name sends half the
> traffic to an address that is no longer the client's.
>
> So `Upsert` deletes the stale records for each (name, type) before saving the new one, with `force` left off. That ordering leaves a sub-second window in
> which the name does not resolve, which is the better of the two failures available: the gap happens during a change that was about to invalidate every cached
> answer anyway, while a duplicate record persists until someone notices. Confirm the endpoint's actual behaviour against a live account; if it does replace an
> RRset, the delete can go and the window with it.

### 10.3 Badger key rotation — open, and `secret rotate` refuses rather than guessing

The mechanism is still assumed rather than verified. Confirm how Badger's key registry handles re-keying before documenting the rotation procedure as
supported.

`protean secret rotate` therefore **returns an error** instead of attempting it. Half-implementing this is the one outcome worth avoiding: a rotation that
fails part way through leaves a database that nothing can open, which is strictly worse than a database that has not been rotated. The error names this
section and gives the manual procedure - export, restart with the new secret, re-import - so an operator who needs it is not simply stuck.

`pkg/kv/badgerkv` already proves the surrounding property that any rotation has to preserve: an encrypted database opens under its own key and refuses both a
missing key and a wrong one.

### 10.4 The `pkg/kv` namespace race — ✅ resolved in Phase 0

Resolved once for all three services, as `docs/IMPLEMENTATION.md` §4 requires. The namespace is now a per-call argument, with an immutable `kv.Handle` binding
one namespace for ergonomics. `SetNamespace` does not exist.

Reading `gopskit`'s `pkg/kv` closely turned up seven further problems that made the port non-mechanical. They are listed here because each one is a behavioural
decision this repository is now committed to:

| #   | Problem in `gopskit`                                        | Resolution                                                                                                    |
| --- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 1   | `SetNamespace` + `currentNamespace` as shared mutable state | namespace is an argument; `kv.Handle` is an immutable value                                                   |
| 2   | one global `sync.Mutex` around _every_ read and write       | removed — it only ever protected (1); Badger is already concurrent and does its own conflict detection        |
| 3   | `Store` exposes `Path()` and `Config() badger.Options`      | off the interface — **no Valkey implementation could satisfy it**. Both live on the concrete `badgerkv.Store` |
| 4   | `Get` returns raw `badger.ErrKeyNotFound`                   | normalised to `kv.ErrNotFound`, so pivot never imports Badger to recognise a missing key                      |
| 5   | `Has` is `len(value) > 0`                                   | reports key existence — a key stored with an empty value **exists**                                           |
| 6   | `Delete` skips the key guard `Get`/`Set`/`Has` apply        | validation is symmetric across every operation                                                                |
| 7   | `ctx`/`cancel` stored on the struct, never used             | context is a per-operation argument and is honoured                                                           |
| 8   | no TTL at all                                               | `kv.WithTTL`, which pivot requires for tokens, rate limits and the cache                                      |

The interface is `Get`/`Set`/`Has`/`Delete`, `Keys`/`Scan`, and three atomic primitives — `SetIfAbsent`, `CompareAndSwap`, `Increment` — each traceable to a
documented requirement rather than speculative. A general multi-key transaction was deliberately **excluded**: Badger transactions and Valkey MULTI/Lua do not
abstract cleanly, and nothing in the three documents needs one.

`pkg/kv/kvtest` is a conformance suite that every implementation runs, so the Valkey store cannot quietly diverge on the awkward cases. `badgerkv` runs it three
times — on disk, in memory, and encrypted. The regression test required by `docs/IMPLEMENTATION.md` §4 writes identical key sets to two namespaces from parallel
goroutines and asserts no crossover; run against a shim reproducing `gopskit`'s design it produces seven `DATA RACE` reports and concrete value crossover, so it
has teeth rather than merely passing.

Two Badger behaviours were discovered by that suite and are now pinned by it:

- **`Entry.WithTTL` truncates expiry to whole Unix seconds** — it computes `uint64(time.Now().Add(dur).Unix())`, and Badger treats `expiresAt <= now` as
  expired. A 150 ms TTL written early in a second is therefore **already expired before `Set` returns**, and even a one-second TTL can lose almost all of its
  life. `badgerkv` sets `Entry.ExpiresAt` from `kv.ExpiresAt` instead, which rounds up. The interface contract is consequently that a TTL is a _lower_ bound: a
  key lives at least its TTL and at most one `kv.TTLGranularity` longer. Sub-second TTLs buy no sub-second precision, which nothing here needs.
- **Optimistic retry alone is not sufficient for a counter.** Eight goroutines incrementing one key exhaust any sane retry budget, because at most one
  transaction commits per round. The read-modify-write operations take a sharded per-key lock first, so transactions queue instead of colliding. This is not (2)
  returning: `Get`, `Set`, `Delete`, `Keys` and `Scan` take no lock, and it is sound only because Badger's exclusive directory lock makes every writer a
  goroutine in this process. The Valkey implementation needs no equivalent — it has server-side atomics and spans replicas.

### 10.5 TLS termination — ✅ resolved 2026-10-06

Decided once for all three services. Both modes are supported and selected by configuration: native TLS from operator-supplied certificate and key files, or
plain HTTP behind a reverse proxy with an explicit `trusted_proxies` list. ACME is **not** implemented — it would add a dependency no design document names, and
an operator terminating TLS natively already has a renewal mechanism.

See §4.1 for the mechanics, including why `trusted_proxies` has no default: in proxy mode that list is the only thing standing between a client and spoofing its
own source address past the per-source rate limiter (§6.4).

### 10.6 Address-history retention default — ✅ resolved 2026-10-07

**90 days**, as `retention.address_history` (`2160h`), changeable at runtime through `protean config set` and disabled entirely by setting it to `0`.

The reasoning, since this is a GDPR-relevant value and not merely housekeeping: IP addresses are personal data (§9.3), so the default has to be defensible as a
retention period rather than merely convenient. 90 days is long enough to answer "when did this host last move", short enough to justify, and the same order as
the conventional default for access logs - which is the comparable artefact. An operator who needs a different number sets one; an operator who needs none sets
zero.

`kv.WithTTL` is the mechanism, so expiry is the store's job rather than a sweeper of protean's own. Note the granularity recorded in §10.4: a TTL is a lower
bound honoured to one second, which is irrelevant at this scale but worth knowing before reusing the mechanism for something short-lived.
