# netory Architecture

This repository contains three self-hosted network services written in Go, built and released together:
[`protean`][protean_readme], a dynDNS control plane; [`signpost`][signpost_readme], a public script router; and
[`pivot`][pivot_readme], a read-only API proxy. Each is a single static executable and a container image.

This document describes how the services work, what they share, and where their limits are. Each service README
owns its installation, configuration and operating reference. [Contributing][contributing] owns the development
workflow and code conventions; the [Security Policy][security] owns vulnerability reporting and trust boundaries.

- [Repository Layout](#repository-layout)
- [Shared Architecture](#shared-architecture)
- [protean](#protean)
- [signpost](#signpost)
- [pivot](#pivot)
- [Build and Distribution](#build-and-distribution)
- [Compliance Notes](#compliance-notes)

## Repository Layout

```text
├── cmd/<service>/            # Thin entrypoint, user-facing README, container image target
├── internal/
│   ├── protean/              # app, cmd, config, server, provider
│   ├── signpost/             # app, cmd, config, server, bundle
│   └── pivot/                # app, cmd, config, server, rules, auth, cache
├── pkg/                      # Packages shared by the services
│   ├── kv/                   # Store interface; badgerkv/, valkeykv/ and the kvtest conformance suite
│   ├── secret/               # Service secret validation and HKDF key derivation
│   ├── seal/                 # Authenticated encryption for values stored outside an encrypted store
│   ├── admin/                # Unix-socket admin server and client, peer credentials
│   ├── forwarded/            # X-Forwarded-* handling: client address and TLS state
│   ├── event/                # Event bus with a persistent outbox, retries, deduplication and claims
│   ├── notify/               # SMTP and HMAC-signed webhook notifiers
│   ├── backup/               # Sealed backups to a filesystem or S3
│   ├── schema/               # JSON Schema generation from Go types
│   ├── log/                  # log/slog wrapper
│   └── stamp/                # Link-time build metadata
├── tests/e2e/                # Container-backed end-to-end tests, behind the `e2e` build tag
├── scripts/                  # Release artifact and build-stamp scripts; bazel/ holds the image macro
└── docs/
    ├── schema/               # Generated JSON Schemas for user-authored documents
    └── examples/             # Example configuration for operators to copy; never installed
```

The Go module path is `github.com/adnoctem/netory`. Application code lives in `internal/<service>`; a package
moves to `pkg/` only when more than one service uses it. `pkg/kv` holds the interface alone, so the protean and
signpost binaries never link the Valkey client.

## Shared Architecture

### Process Model

Each service is one binary with two roles. `<service> server start` runs the long-lived server; every other
subcommand is a short-lived client of a running server. The server exposes two listeners with different exposure:

| Listener    | Exposure                 | Authentication                                                    |
| ----------- | ------------------------ | ----------------------------------------------------------------- |
| Service API | Network, HTTPS           | Per service: host tokens, none (public reads), client credentials |
| Admin API   | Local Unix domain socket | File permissions on the socket and its directory                  |

protean and signpost are single-replica: the server is the only process that opens their Badger database, and
Badger's exclusive directory lock enforces that at the filesystem level. pivot runs as several stateless replicas
over a shared Valkey.

### Administration

Administration is local. There is no network administration API in any service; remote administration goes
through SSH, `docker exec` or `kubectl exec`, and then the local CLI. The admin socket is created `0600` inside a
`0700` directory owned by the service user, so reaching it requires being that user or root. The connecting
process's credentials are read from the kernel (`SO_PEERCRED`) for the audit record; they identify the caller,
they do not authorise it.

The CLIs use Cobra with Git-style noun-verb ordering, such as `protean host add`, `signpost bundle publish` and
`pivot rules test`. `secret generate` and `version` work without a server in all three, as do `signpost bundle
validate` and `pivot rules validate`. Every administrative mutation is written to an audit log naming the
operator, the action and the time; reads are logged at debug level. `list` output never prints a credential.

Configuration has two layers. Bootstrap configuration - listen address, socket path, store location, TLS files,
trusted proxies, logging - is needed before the store can be opened and comes from flags and environment
variables. Runtime settings live in the store, are changed with `<service> config set`, and take effect without
a restart. `<service> config view` shows both together.

### TLS and Forwarded Headers

Every service supports two modes, selected by configuration: native TLS from operator-supplied certificate and
key files, or plain HTTP behind a reverse proxy. ACME is not implemented.

In proxy mode, `X-Forwarded-For` and `X-Forwarded-Proto` are honoured only from a peer inside the configured
`trusted_proxies` list, which has no default. That list decides the client address used for rate limiting, events
and logs, and - for signpost - whether a request can be confirmed as encrypted. An over-broad list lets a client
choose its own apparent address. The parsing is shared in `pkg/forwarded`.

### Secrets and Key Derivation

Each service takes exactly one high-entropy secret: `PROTEAN_SECRET`, `SIGNPOST_SECRET` or `PIVOT_SECRET`,
delivered as an environment variable, a file, a systemd credential or a container secret. A secret shorter than
32 bytes after decoding is rejected, and `<service> secret generate` produces a valid one from `crypto/rand`.

Every key in use is derived from the secret with HKDF-SHA256 under a purpose-specific label, such as
`protean/kv-encryption`, `protean/webhook-signing` or `pivot/credential-encryption`, so one recovered key reveals
nothing about another. The raw secret is never passed to a consumer. HKDF rather than a password-based derivation
is sufficient because human-chosen secrets are refused.

`<service> secret rotate` is not implemented in any service; it refuses and prints the manual procedure for that
service: [protean](#protean-known-limitations), [signpost](#signpost-known-limitations),
[pivot](#pivot-known-limitations).

### Storage

`pkg/kv` defines one store interface with two implementations:

| Implementation | Used by           | Properties                                                               |
| -------------- | ----------------- | ------------------------------------------------------------------------ |
| `badgerkv`     | protean, signpost | Embedded, encrypted at rest with a derived AES-256 key, single process   |
| `valkeykv`     | pivot             | Shared by replicas, no encryption at rest, server-side atomic operations |

The interface is `Get`, `Set`, `Has`, `Delete`, `Keys`, `Scan` and three atomic operations: `SetIfAbsent`,
`CompareAndSwap` and `Increment`. Every operation takes the namespace as an argument; `kv.Handle` binds one
namespace for convenience and is immutable. There is no general multi-key transaction.

Behaviour both implementations guarantee, enforced by the shared `pkg/kv/kvtest` conformance suite:

- A missing key is `kv.ErrNotFound`. A key stored with an empty value exists. Deleting an absent key succeeds.
- A TTL is a lower bound honoured to one second: a key lives at least its TTL and at most one second longer.
  Sub-second expiry is not expressible.
- A write without a TTL clears any expiry the key had.
- `Keys` and `Scan` return entries in unspecified order, and are too expensive on Valkey for a request path.
- `Increment` stores decimal ASCII and fails with `kv.ErrNotAnInteger` on any other value.

On Valkey, `CompareAndSwap` and the expiring `Increment` are Lua scripts, so the comparison and the write happen in
one server-side execution. On Badger, read-modify-write operations take a sharded per-key lock before their
transaction, which is sound because every writer is in the same process.

### Encryption of Stored Values

protean and signpost rely on Badger's encryption at rest. Valkey has none, so pivot seals every sensitive value
with `pkg/seal` - AES-256-GCM under a derived key, with the format header bound as additional data - before it is
written. Hashes stand in for values that only ever need comparing: client secrets, host tokens and issued access
tokens are stored as SHA-256 hashes and looked up by hash.

### Events and Notifications

Each service emits typed events onto an in-process bus. Notifiers subscribe and deliver them by SMTP or HTTP
webhook. Delivery goes through a persistent outbox stored in the service's own store:

- Events are persisted before delivery is attempted, so a restart or a relay outage delays a notification rather
  than losing it. Failed deliveries are retried with backoff; delivery is at-least-once.
- Identical events can be collapsed within a configurable window (`events.dedup_window`).
- SMTP uses the operator's relay, implicit TLS on port 465 or STARTTLS on 587. Header values built from event data
  have CR and LF removed and subjects are RFC 2047-encoded, so an attacker-influenced field cannot add a header.
- Webhook bodies are JSON, signed with HMAC-SHA256 under a key derived from the service secret.
- Notifier credentials are stored like other credentials and redacted from every listing.
- `<service> outbox status` shows pending, failed and claimed entries.

On pivot, several replicas share one outbox. Each pending entry can carry a claim - a holder and an expiry - taken
with `CompareAndSwap`, so two replicas cannot deliver the same attempt. An expired claim is claimable by anyone,
which recovers entries held by a replica that stopped. A failed attempt drops its claim so any replica may retry
it, and a shutdown releases claims it had not reached.

### Generated Schemas

The two documents users write by hand have JSON Schemas generated from the Go types that validate them:
[`signpost-manifest-v1.json`][schema_manifest] and [`pivot-rules-v1.json`][schema_rules]. `pkg/schema` generates
both. Property names, types, required fields and `additionalProperties: false` come from the structs; bounds,
patterns and enumerations come from the constants the validators use. A test in each package fails if the
committed file differs from the generated one.

A schema describes a well-formed document, not an accepted one. Checks JSON Schema cannot express - route
uniqueness, files that must exist in an archive, regular expressions that must compile, limits across two arrays -
stay in Go, which is what the services and their `validate` commands run.

Both schemas declare an `$id` under `https://adnoctem.github.io/netory/schema/`, built from `pkg/schema.BaseURL`.
That URL does not currently serve the documents; editors must be pointed at the files directly.

### Configuration Examples

Services install no configuration on an operator's behalf. Documents an operator may want to start from live in
[`docs/examples`][examples], are covered by tests that compile every file there, and are applied explicitly.

### Dependencies and Extensibility

- No cgo and no runtime plugin loading. DNS providers and notifiers are compiled in and register at `init`;
  adding one is a code change and a rebuild. The release configuration disables cgo, so a dependency that
  requires it cannot be released.
- Third-party libraries sit behind interfaces this repository owns: the DNS provider interface, the notifier
  interface and the store.
- The standard library is the default. Notable dependencies are Badger, valkey-go, libdns with its Cloudflare and
  Route 53 packages, aws-sdk-go-v2 for Route 53 and S3, Cobra, `gopkg.in/yaml.v3` and `golang.org/x/crypto` for
  BLAKE2b. `go.mod` and `MODULE.bazel` are the complete list.

## protean

### protean Scope

protean accepts address updates from dynDNS clients and writes them to an existing DNS provider. It hosts no
zones and is not an authoritative name server: every record it touches lives at Cloudflare, Route 53 or Spaceship,
and the provider remains the source of truth. Remote management, runtime plugins and Windows are out of scope.

### Update API

The update endpoint speaks DynDNS2, so ddclient, inadyn and routers such as the FRITZ!Box work unchanged.

- `GET` or `POST /nic/update`, authenticated with HTTP Basic: the password is the token. TLS is mandatory, either
  natively or confirmed through a trusted proxy.
- The token authenticates and identifies the host; one token belongs to one host. A hostname may be asserted in
  the `hostname` parameter or as the username and must then match the token's host. A username that is not a
  well-formed hostname is treated as a username, not a claim.
- Parameters: `hostname`, `myip` (IPv4 or IPv6) and `myipv6`. The request's source address is used only when no
  address is given.
- Responses use the DynDNS2 codes `good`, `nochg`, `badauth`, `nohost`, `notfqdn`, `abuse`, `dnserr` and `911`,
  with a matching HTTP status so failures are visible in proxy access logs. A valid token presented for another
  hostname gets `nohost`.
- Credentials in the query string are refused with an explanatory log entry, because a URL is logged by every
  proxy it passes.
- A and AAAA records update independently, which matters on DS-Lite connections where the observed IPv4 address
  belongs to the carrier.

### Tokens

Tokens are 32 random bytes, shown once when created and never retrievable. They are stored as SHA-256 hashes and
looked up by hash, so a presented token is never compared against a stored secret; the host check afterwards uses
a constant-time comparison. A host can have several tokens, so `token rotate` replaces one without downtime and
`token revoke` takes effect immediately. Removing a host revokes its tokens but leaves its DNS records.

### Abuse Protection

- A per-source limit applies before authentication, to slow token guessing; a per-host limit applies after it.
- An unchanged address answers `nochg` without calling the provider.
- Repeated authentication failures raise an `auth.failed` event after a configurable threshold.

### DNS Providers

Providers implement one narrow interface covering A, AAAA and TXT records for single names:

```go
type Provider interface {
    Name() string
    Get(ctx context.Context, zone, name string) ([]Record, error)
    Upsert(ctx context.Context, zone string, records []Record) error
    Delete(ctx context.Context, zone string, records []Record) error
}
```

| Provider   | Implementation                                   | Credentials                                              |
| ---------- | ------------------------------------------------ | -------------------------------------------------------- |
| Cloudflare | libdns adapter                                   | Scoped API token, optionally a separate zone-read token  |
| Route 53   | libdns adapter                                   | AWS credential chain, or an access key stored in protean |
| Spaceship  | Native client for `https://spaceship.dev/api/v1` | API key and secret                                       |

The libdns adapter depends only on the libdns methods protean calls, so changes elsewhere in libdns cannot reach
protean. Spaceship's API is not Namecheap's; a domain hosted at Namecheap itself needs a different provider. A
provider cannot be removed while a host references it. Credential scoping - zone-limited tokens, IAM policies
restricted to the hosted zone - is the operator's responsibility; providers offer no way to inspect it.

### protean Storage and Backups

State lives in an encrypted Badger database: hosts, token hashes, provider and notifier credentials, settings,
address history and the outbox. Address history expires after `retention.address_history`, 90 days by default.

`protean backup create | list | verify | restore` writes backups to a local directory or to S3. Badger's own backup
stream is plaintext even for an encrypted database, so every backup is sealed with AES-256-GCM under a key derived
at its own label, with a random nonce per backup. A backup is therefore only restorable with the secret that made
it. A backup is held in memory and limited to 1 GiB.

`create`, `list` and `verify` run in the server through the admin socket; S3 credentials come from the AWS
credential chain of the server process. `verify` decrypts without restoring and exits non-zero on failure.
`restore` is offline: the server must be stopped, and a non-empty database is refused unless forced, because
Badger's load merges rather than replaces.

### protean Events

| Event                             | Trigger                                         |
| --------------------------------- | ----------------------------------------------- |
| `host.updated`                    | Address change written to the provider          |
| `host.update_failed`              | Provider call failed after retries              |
| `auth.failed`                     | Repeated `badauth` for a host or source address |
| `token.created` / `token.revoked` | Token lifecycle through the CLI                 |
| `provider.failed`                 | Provider unreachable or credentials rejected    |

### protean Known Limitations

- `secret rotate` is not implemented. How Badger's key registry behaves under re-keying is unverified, and a
  partial rotation would leave an unreadable database. The manual procedure is export, restart with the new
  secret, and re-import.
- Spaceship's save endpoint is not documented to replace an existing record set, so `Upsert` deletes stale
  records before saving. A name can briefly fail to resolve during an address change. This has not been verified
  against a live account.
- protean runs as a single replica.

## signpost

### signpost Scope

signpost serves scripts for the one-line install pattern, such as `curl -fsSL https://example.org/install.sh | sh`.
It takes a bundle of scripts plus one manifest and serves each script at a configured path. Clients execute what
it serves without review, so the integrity of every byte served is its central property. Authenticated downloads,
a remote publishing API, executing scripts on the server and Windows are out of scope.

### Bundles and Manifest

A bundle is one `.zip` or `.tar.gz` archive with exactly one manifest at its root, named `signpost.yaml`,
`signpost.yml` or `signpost.json`:

```yaml
version: 1
release: 1.4.0
description: shown by `signpost bundle list`
routes:
  - path: /install.sh
    file: scripts/install.sh
  - path: /install.ps1
    file: scripts/install.ps1
    content_type: text/plain; charset=utf-8
```

`content_type` is optional and inferred from the extension: shell scripts as `text/x-shellscript`, `.json` as
`application/json`, and anything else as `text/plain` so a script can be read before it is piped. Unknown manifest
keys are rejected. `skip_truncation_check` opts one route out of the truncation check.

### Validation

`bundle validate` runs locally and `bundle publish` runs the same validation in the server, which is the one
trusted. A bundle failing any step is rejected whole:

1. The archive is well-formed and within limits: 64 MiB compressed, 256 MiB uncompressed, 8 MiB per file and 4096
   entries.
2. Absolute paths, `..` segments, symlinks and hardlinks are refused.
3. Exactly one manifest exists and is valid.
4. Every route references a file in the archive; paths are unique and avoid reserved paths - the health path,
   `.sha256` suffixes and `/v<release>/` prefixes.
5. Every shell and PowerShell route passes the truncation check.

Archives are held in memory and never unpacked onto a filesystem. When a signature is required, it is verified
before the archive is opened, so unverified input never reaches the extractor.

### Releases, Aliases and Serving

Every publish creates an immutable release. Aliases such as `latest` and `stable` point to one release each, and
the unversioned routes serve whichever release the serving alias names. Every release is also reachable at
`/v<release>/<path>` for pinned installs.

- Publishing a release identifier that exists is refused; release creation uses `SetIfAbsent`.
- An alias moves with `CompareAndSwap` against the release it was read at, so a concurrent publisher is told the
  alias moved instead of overwriting it.
- Content is written first, then the release record, then the alias, then the in-memory route table, which is
  swapped whole. No request observes a partly published release.
- `bundle rollback` moves an alias back one step; a second rollback undoes the first.
- `bundle remove` deletes a release that no alias references.

Release metadata lives in Badger. Script contents live in a separate content directory, one subdirectory per
release, each file named after its SHA-256 and created `0600`. Content is verified against its digest on every
uncached read, so a file altered on disk fails the request instead of being served.

### Response Behaviour

- `Content-Type` from the manifest and `X-Content-Type-Options: nosniff`.
- A SHA-256 checksum per route at `<path>.sha256`, in `sha256sum` format.
- An explicit `Content-Length` on every response, which lets a piping client detect truncation.
- `ETag` from the content hash. Alias routes have short cache lifetimes and versioned routes long ones, set by
  `cache.alias_max_age` and `cache.versioned_max_age`.
- `X-Signpost-Release` names the release served.
- Unknown paths return 404 without listing routes. One path always serves one byte sequence: there is no content
  negotiation, and scripts are served verbatim without templating.

### HTTPS Enforcement

Scripts are served only over a connection confirmed as encrypted: native TLS, or a trusted proxy reporting
`X-Forwarded-Proto: https`. Any other request receives `421 Misdirected Request` instead of a script or a
redirect, since a client that followed a redirect would already have sent its request in the clear.

### Signatures

Bundles can carry a detached minisign signature, verified on publish against a trusted public key configured
with `publish.signing_key`; `publish.require_signature` makes it mandatory. Both minisign algorithms are
supported - `Ed`, Ed25519 over the file, and `ED`, Ed25519 over its BLAKE2b-512 hash - and both the signature and
the global signature over the trusted comment are checked. signpost verifies only; it holds no signing key. A
signature that is supplied but cannot be verified is an error, never a silent downgrade to unsigned. Signature
status and the trusted comment are recorded with the release.

PowerShell scripts can be Authenticode-signed before bundling; signpost serves them unchanged.

### Truncation Protection

A dropped connection can make a shell execute part of a script. signpost therefore requires each shell and
PowerShell route to wrap its logic in definitions invoked only on the last line:

```sh
main() {
    # install logic
}
main "$@"
```

A script passes when every top-level statement is either prelude - comments, shebang, plain assignments to
literals, option setting, definitions - or an invocation of a function the file defines, and the last non-empty
line is such an invocation. The PowerShell check applies the same rule to `#Requires`, `param(...)`,
`Set-StrictMode`, `using` statements and `function`, `filter` and `class` definitions. An assignment from a
command substitution counts as a command. Unrecognised top-level constructs are refused, as is a `.sh` or `.ps1`
route that cannot be classified.

Both checks are structural heuristics: they establish that a script can only act once fully received, not that it
is safe, and they can reject a legitimate script. `skip_truncation_check` on a route bypasses the check; the
bypass is recorded on the release, reported by `bundle list` and carried in the publish event, and
`publish.allow_truncation_opt_out` can refuse it.

### signpost Events

| Event              | Trigger                          |
| ------------------ | -------------------------------- |
| `bundle.published` | New release created              |
| `bundle.rejected`  | Validation failed on publish     |
| `alias.changed`    | Alias moved, including rollbacks |
| `bundle.removed`   | Release deleted                  |

Deduplication is off by default, because every signpost event is a deliberate administrative act and a
publish-then-rollback sequence must produce both notifications.

### Access Log

Each request is logged with the method, path, status, bytes, duration, release served, client address and
User-Agent. `accesslog.client_address` is
`full`, `anonymised` or `off`, defaulting to `anonymised` - IPv4 truncated to a `/24`, IPv6 to a `/48` - and the
reduction happens before the record reaches any log handler. Client-controlled fields are bounded and stripped of
control characters. Retention belongs to the operator's log pipeline; the access log leaves the process
immediately.

### signpost Known Limitations

- `secret rotate` is not implemented. The manual procedure is to start with the new secret against an empty
  database and republish the releases needed.
- signpost runs as a single replica; read traffic scales through a CDN or caching proxy.
- The schemas' `$id` URLs are not served. signpost can serve them as an ordinary bundle, with routes matching the
  `$id` paths and `pkg/schema.BaseURL` pointed at that host.

## pivot

### pivot Scope

pivot sits between customers and a production API. It issues its own credentials, authenticates to the backend
on each customer's behalf, filters requests by path rules, and protects the backend with rate limits, a
concurrency cap and a response cache. Customers use the backend's documentation and existing clients. The
Shopware 6 Admin API is the reference backend, but nothing in pivot is specific to it: a backend is a rule set plus
authentication configuration.

Response filtering, request transformation, documentation hosting, remote management and Windows are out of
scope.

### Two Layers of Access Control

Two independent layers must both fail before a customer reaches data they should not see:

1. **Path rules** in pivot: deny-by-default allow and deny lists over method and normalized path.
2. **Backend authorization:** each customer has its own backend credential with its own permissions - for
   Shopware, one integration with a restricted ACL role.

Path rules see only direct routes. Data reachable through associations of an allowed entity is controlled by the
backend's permissions alone, which is why the second layer is required. The backend must not be reachable by
customers directly.

### Replicas and State

All shared state is in Valkey and replicas hold nothing that cannot be lost, so any number can run without
coordination. Every replica must be given the same `PIVOT_SECRET`; a replica with a different secret starts and
then fails every forward leg, because stored backend credentials were sealed under the other secret.

| Data                                | Stored as                       |
| ----------------------------------- | ------------------------------- |
| Client IDs and secrets              | SHA-256 hash                    |
| Issued access tokens                | SHA-256 hash with TTL           |
| Backend credentials, backend tokens | Sealed with AES-256-GCM         |
| Notifier credentials                | Sealed with AES-256-GCM         |
| Rate-limit buckets                  | Plain, with expiry              |
| Cached responses                    | Plain, or sealed per route      |
| Outbox and audit records            | Plain, audit records with a TTL |

Rules, clients and settings share one version counter in Valkey. Each change increments it and publishes an
announcement; every replica subscribes to the announcement and also polls the counter every 15 seconds, then
rebuilds its compiled rule table when the version moved. The announcement makes convergence fast; the poll makes
it certain, because a pub/sub message sent while a replica is reconnecting is lost. The compiled table sits behind
an atomic pointer, so a request never sees a partly updated rule set. The replica that made a change rebuilds
immediately.

### Request Pipeline

The proxy listener dispatches requests itself rather than through `http.ServeMux`, which would clean
non-canonical paths and answer them with a redirect before any rule ran. Every request then passes these stages,
any of which can end it:

1. **Normalize:** strip method-override headers; refuse any method other than `GET`, `HEAD` and `POST` with 405
   before any rule set is consulted; normalize the path and reject an ambiguous one with 400; refuse a request
   confirmed as plaintext with 426.
2. **Answer the token endpoint** at `frontend.auth_path` locally; it is never forwarded.
3. **Authenticate** the client from its pivot credentials; 401 on failure.
4. **Evaluate rules:** deny, then allow; 403 on a deny or no match.
5. **Rate limit** per client; 429 with `Retry-After`.
6. **Cache lookup** for cacheable routes.
7. **Coalesce** identical concurrent requests for cacheable routes into one backend call.
8. **Acquire a backend slot** within the per-replica concurrency limit, or fail with 503.
9. **Forward** the normalized request with the client's backend credentials, without the client's own
   `Authorization` header.
10. **Store and respond:** cache when the route allows it, record the outcome, emit events.

Rejections are ordered so that unauthenticated, denied and rate-limited traffic never costs a backend call. A 401
does not say whether the client or the secret was wrong, and a 403 does not say which rule matched.

A request whose encryption cannot be determined - proxy mode without a trusted proxy reporting the scheme - is
accepted, and the startup log warns about that configuration.

### Path Normalization

Rules are only as strong as the path they match, so pivot normalizes before matching and forwards the normalized
path; pivot and the backend's router see the same request.

- Percent-escapes of unreserved characters are decoded (RFC 3986 §6.2.2.2); other escapes stay encoded with
  uppercase hex. Encoded `/`, `\` and null bytes are rejected with 400, as is a literal backslash.
- Repeated slashes are collapsed and `.` and `..` resolved; a path climbing above the root is rejected.
- A trailing slash is dropped, so each route has exactly one spelling. A backend routing `/x` and `/x/` to
  different handlers cannot be distinguished.
- Matching is case-sensitive.

A reverse proxy in front of pivot must pass the path through unmodified; one that rewrites or re-encodes it
reintroduces a second interpretation.

### Rule Documents

A rule document is YAML or JSON, detected from its content, limited to 1 MiB and 512 entries, with unknown keys
rejected:

```yaml
rules:
  deny:
    - { methods: ["*"], glob: "/api/_action/**", comment: "why this is denied" }
  allow:
    - { methods: [GET], regex: "/api/[a-z0-9-]+(/[0-9a-f]{32})?" }
    - { methods: [POST], glob: "/api/search/*" }
routes:
  - { glob: "/api/search/order", cache: { ttl: 1m, encrypt: true } }
```

- **Globs:** `*` and `?` match within a segment and `**` across segments. `**` must be a whole segment; `***` and
  patterns ending in `/` are refused. Matching uses a dynamic-programming table, so a pattern cannot degrade
  exponentially against an attacker-chosen path.
- **Regular expressions:** RE2, anchored at both ends automatically, with linear-time matching.
- **Methods:** names are case-insensitive. `*` means every forwardable method and is accepted on deny rules only;
  an allow rule must name its methods. A rule naming a write method is a compile error.
- **Matching** is whole-path, and each entry declares its pattern kind explicitly.
- **Comments** on rules appear in `rules list`, `rules test` and the audit record of a request the rule decided.
- A document that does not compile is never stored. `pivot rules validate` runs the same compiler without a
  server; `pivot rules test <path>` shows the normalized path, the verdict and the deciding rule.

A route's `ttl` is a duration string in YAML (`1m`) but an integer count of nanoseconds in JSON, because the
document decodes into Go's `time.Duration`; `"ttl": "1m"` in JSON is rejected.

pivot ships no rule set. A fresh instance denies everything and reports itself not ready until a rule set is
applied. [`docs/examples/pivot`][examples_pivot] holds a read-only Shopware 6 rule set and a deny-all document;
`pivot rules apply --deny-all` applies the latter without a file.

### Global and Per-Client Rules

There is one global rule set and optional per-client additions, combined by accumulation: deny lists are
concatenated, allow lists are concatenated, and the result is evaluated deny-first. A client's rules can grant a
path the global set does not and can add restrictions, but cannot reopen a path the global deny list refuses.
Global denies are evaluated before client denies, so the audit record names the global rule when both match.

A client whose own rules fail to compile falls back to the global set, and the failure is logged. Cache routes
work the other way: a client route overrides the global route for its path.

### Authentication

Frontend and backend authentication are configured independently. Customers only ever hold pivot credentials;
backend credentials never leave pivot.

| Side     | Purpose                                | Modes                                                           |
| -------- | -------------------------------------- | --------------------------------------------------------------- |
| Frontend | How customers authenticate to pivot    | `oauth2` (client-credentials emulation), `http-basic`, `bearer` |
| Backend  | How pivot authenticates to the backend | `oauth2` (client credentials), `http-basic`, `api-key`          |

In frontend `oauth2` mode pivot answers the token endpoint itself with the backend's response shape (RFC 6749
§5.1), so existing clients work unchanged. Client secrets are random, shown once and stored hashed. Issued tokens
are opaque, short-lived (`token.lifetime`), stored hashed with their expiry, and revoked when the client is
disabled. In backend `oauth2` mode, backend tokens are fetched, refreshed before expiry and shared by replicas
through Valkey.

### Load Protection

| Mechanism          | Scope       | State           | Purpose                                            |
| ------------------ | ----------- | --------------- | -------------------------------------------------- |
| Rate limit         | Per client  | Valkey (shared) | Fairness and abuse protection                      |
| Concurrency limit  | Per replica | In memory       | Cap simultaneous backend calls                     |
| Request coalescing | Per replica | In memory       | One backend call for identical concurrent requests |

The rate limit is a token bucket evaluated in one Lua script, so concurrent checks from several replicas cannot
spend the same token. Its capacity is the burst a client may take at once and its rate what it may sustain;
fractional rates are allowed. Refill is computed from elapsed time, with a clock that runs backwards treated as no
time elapsed. A capacity of zero means unlimited, and `Retry-After` is at least one second.

The concurrency limit is enforced per replica, so the effective limit on the backend is `backend.concurrency`
multiplied by the replica count.

Cacheable routes are buffered, limited to 32 MiB, because caching and coalescing need the complete body.
Uncacheable routes are streamed without a size limit and are not coalesced.

### Cache

- Only routes listed under `routes` are cached, each with its own TTL. `GET` and allowed `POST` searches are
  cacheable.
- The key covers the client, method, normalized path, canonical query string and a hash of the canonical body.
  `shared: true` drops the client from the key, which is correct only when the response cannot differ between
  clients.
- Backend `Cache-Control: no-store` and `private` are honoured.
- `encrypt: true` seals the cached body under a derived key. It is off by default; pivot cannot tell from a path
  whether a response carries personal data.
- `pivot cache purge` clears cached entries.

### Health and Readiness

`/healthz` reports that the process is alive and touches nothing else. `/readyz` reports whether the replica can
serve: Valkey reachable and a global rule set containing at least one allow rule. A fresh instance is therefore
not ready, and so is one switched off with `rules apply --deny-all` - a load balancer stops routing to it rather
than letting customers receive 403 for every request.

### pivot Events

| Event                 | Trigger                                                       |
| --------------------- | ------------------------------------------------------------- |
| `client.auth_failed`  | Repeated failed authentication for a client or source address |
| `rule.denied`         | Requests denied by a rule (aggregated)                        |
| `client.rate_limited` | Client exceeded its limit (aggregated)                        |
| `backend.failed`      | Backend errors or timeouts above threshold                    |
| `backend.auth_failed` | Backend rejected pivot's credentials                          |

Denials and rate-limit events are aggregated per replica before notification; the per-request log line is emitted
regardless.

### Audit

The per-request record - client, method, normalized path, matched rule, status and latency - goes to the
structured log, without request or response bodies, and its retention belongs to the operator's log pipeline.
Administrative actions and aggregated security outcomes are also stored in Valkey for `audit.retention`, 90 days
by default, so any replica can answer `pivot audit` queries. Client addresses follow `accesslog.client_address`
as in signpost.

### pivot Known Limitations

- pivot is read-only by construction. Only `GET`, `HEAD` and `POST` are forwardable; no configuration enables
  writes.
- The example Shopware rule set has been exercised against the Admin API's request shapes, not checked against the
  full route list of a given Shopware version. An allow rule broader than intended is bounded by the backend
  credential's permissions.
- The backend concurrency limit multiplies with the replica count.
- `secret rotate` is not implemented. The manual procedure is to stop every replica, start them with the new
  secret, re-enter each client's backend credentials with `pivot client backend`, and re-create each notifier.

## Build and Distribution

### Build System

The build uses Bazel with Bzlmod and Gazelle-generated `BUILD` files. `.bazelversion` and `MODULE.bazel` pin
Bazel, rules_go, Gazelle and the Go SDK; the Go SDK version also appears in `go.mod`. No C toolchain is registered.
`--config=release` builds optimised, statically linked, stripped binaries with cgo disabled. Race-detector testing
needs cgo and therefore runs as a separate configuration.

`scripts/bazel-create-status.sh` produces the build stamp - version, commit, branch, Go version, build date and
platform - which each binary reports with `<service> version`. It depends only on Bash, Git and coreutils.

### Release Artifacts

`scripts/release-create.sh` builds every service for `linux/amd64`, `linux/arm64`, `darwin/amd64` and
`darwin/arm64`, and packages per target:

- `<service>_<os>_<arch>.tar.gz` with one binary, `LICENSE` and `README.md`;
- `netory_<os>_<arch>.tar.gz` with all three binaries;
- `CHECKSUMS_SHA256.txt` covering every tarball.

Archive entries are owned by root. File names carry no version, so
`https://github.com/adnoctem/netory/releases/latest/download/<file>` always names the newest release; the tag in
`releases/download/<tag>/<file>` pins one.

### Container Images

Each service is published as `ghcr.io/adnoctem/<service>`, a multi-architecture index for `linux/amd64` and
`linux/arm64`, tagged with the release version and `latest`. One macro, `scripts/bazel/image.bzl`, defines all
three.

- The base is `gcr.io/distroless/static-debian12:nonroot`, pinned by digest. It provides the CA bundle the
  services need for outbound TLS and nothing else: no shell and no package manager.
- Images run as uid and gid 65532 and satisfy the restricted Pod Security Standard without overrides.
- The binary is `/<service>`, mode `0555`, and is the entrypoint. Images are built with `--config=release`.
- State directories exist in the image with the service's ownership: each leaf `0700` owned by 65532 under
  root-owned `0755` parents. protean writes `/var/lib/protean`, signpost `/var/lib/signpost/db` and
  `/var/lib/signpost/content`, and every service `/run/<service>` for its admin socket.

Administration in a container runs the binary directly, for example `docker exec <container> /pivot config view`.
A read-only root filesystem requires an `emptyDir` with `fsGroup` over `/run/<service>`, which leaves the socket
directory group-writable rather than `0700`.

### Release Process and Versioning

Versions follow Conventional Commits through semantic-release. The project is in 0.x: features and breaking
changes increment the minor version and fixes the patch version. The release script refuses any version that is
not a plain `0.x.y`.

Releasing is manual and gated: the Release workflow acts only when the `NETORY_RELEASE_ENABLED` repository
variable is `true` and the workflow is dispatched, and it refuses a branch that has advanced past the commit the
Testing workflow verified. A release publishes the tarballs and checksums as GitHub release assets and pushes the
three images, built from the release tag without a shared build cache. The prepared artifacts are retained for 14
days so that a partial publication can be completed without rebuilding. The release procedure is in
[Contributing][contributing_releases].

### Platform Support

Linux is the only platform the services are supported on as servers. macOS binaries are published for the
subcommands that need no server. No Windows binaries are published.

## Compliance Notes

### ISO 27001

- Generation, delivery and rotation of each service secret fall under A.8.24 Cryptography and should be part of
  the operator's key-management documentation.
- Administrative actions are audited with the operator's identity from the kernel, the action and the time.
- signpost distributes executable content and is a high-risk asset for change management. Releases are retained,
  so any script ever served can be reproduced.
- pivot records every request's client, path, matched rule and outcome, without bodies.

### GDPR

IP addresses are personal data.

- protean keeps address history for `retention.address_history`, 90 days by default, and `0` disables it.
- signpost and pivot anonymise client addresses in their logs by default.
- pivot keeps its own audit records for `audit.retention`, 90 days by default, and may cache personal data in
  responses; `encrypt` per route seals such entries.
- The choice of SMTP relay and webhook receivers, and any resulting data processing agreement, is the operator's.

Retention periods are configurable because the appropriate period depends on the operator's obligations.

<!-- File references -->

[protean_readme]: ../cmd/protean/README.md
[signpost_readme]: ../cmd/signpost/README.md
[pivot_readme]: ../cmd/pivot/README.md
[contributing]: CONTRIBUTING.md
[contributing_releases]: CONTRIBUTING.md#-releases
[security]: SECURITY.md
[schema_manifest]: schema/signpost-manifest-v1.json
[schema_rules]: schema/pivot-rules-v1.json
[examples]: examples
[examples_pivot]: examples/pivot
