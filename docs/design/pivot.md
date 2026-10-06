---
type: design-document
status: draft
project: netory
created: 2026-10-06
tags:
  - design-doc
  - golang
  - netory
  - proxy
  - valkey
---

# Design Document: pivot (Transparent API Proxy)

## 1. Overview

`pivot` is a transparent API proxy in the `netory` monorepo. It sits between customers and production APIs: it issues its own credentials, authenticates to the
backend on the customer's behalf, filters requests by path rules, and protects the backend with rate limits and caching. Customers use the backend's own API
documentation; pivot is invisible to their clients.

The first backend is the Shopware 6 Admin API. Nothing in pivot is Shopware-specific — Shopware support is a default rule set plus auth configuration.

The design constraint that drives everything else: **two independent layers must both fail before a customer reaches data they should not see.**

1. **pivot path rules:** deny-by-default allow and deny lists on method + normalized path.
2. **Backend authorization:** one backend credential per customer with its own permissions (in Shopware: one integration with a restricted ACL role).

**In scope:** transparent passthrough, frontend and backend auth, path rules, rate limiting, backend concurrency limits, response caching, notifications, local
CLI administration.

**Out of scope:** response field filtering, API documentation hosting, request transformation, remote management, Windows as a supported platform.

> [!INFO] Related
> Shares the `netory` monorepo and the Bazel build setup with [[protean]] and [[signpost]], and reuses their `pkg/` packages — see §8.2 for the `pkg/kv` change
> pivot requires. The layout follows the `gopskit` conventions.

---

## 2. Core Architecture & Principles

- **Two Independent Layers:** path rules and backend permissions are enforced separately and must both fail before data leaks. Neither is trusted to be
  sufficient alone.
- **Deny by Default:** rules are an allow list and a deny list; deny is evaluated first, and a request matching neither is denied. A missing rule is never an
  implicit permission.
- **Normalize Once, Match and Forward the Same Path:** rules are only as strong as the path they match, so pivot canonicalizes the path _before_ matching and
  forwards the normalized form. pivot and the backend's router always see the same request — there is no second interpretation for an attacker to exploit.
- **Transparent to Clients:** pivot emulates the backend's own token endpoint and response shapes. Existing clients work unchanged, against the backend's own
  documentation.
- **Credentials Never Leave pivot:** customers only ever hold pivot credentials. Backend credentials are stored encrypted and used only on the forward leg.
- **Cheap Rejections First:** the request pipeline is ordered so that denied, unauthenticated, or rate-limited traffic never costs a backend call.
- **Stateless Replicas:** all shared state lives in Valkey, so replicas hold nothing that cannot be lost and need no consensus between them. This is what
  separates pivot from its single-node siblings.
- **Backend-Agnostic Core:** a backend is a rule set plus auth configuration. Nothing backend-specific belongs in the proxy itself.
- **Secrets Derived, Never Used Raw:** one high-entropy `PIVOT_SECRET` enters the process; every key in use is derived from it via HKDF with a purpose-specific
  info label.

---

## 3. Repository & Process Architecture

pivot lives in the `netory` monorepo next to [[protean]] and [[signpost]], with the same build setup: Bazel (Bzlmod) and Gazelle, `gopskit` layout, no cgo, MIT
licence, pinned at Bazel 9.2.0 / rules_go 0.64.1 / Gazelle 0.54.0 / Go 1.26.8 SDK (verified in Phase 0, see [[protean]] §10.1). Application code sits in
`internal/pivot/{app,cmd,config,server,rules,auth,cache}`, exactly as drafted — the rate limiter went into `app` because it is Valkey-backed state, and the
concurrency limiter and the coalescer into `server` because §7.1 makes both per replica and in memory.

End-to-end tests live in `tests/e2e/pivot` behind an `e2e` build tag, outside the Bazel build: they need a Docker socket and a Go toolchain to build the binary
under test, and `bazel test //...` promising to run them while silently skipping them would be worse than not offering them.

Unlike protean and signpost, **pivot is designed for several replicas.** All shared state lives in Valkey, so each replica is stateless and no consensus between
replicas is needed.

Each replica exposes two listeners:

- **Proxy (HTTPS, network-facing):** customer traffic.
- **Admin API (Unix domain socket, local only):** used by the CLI. Access is controlled by socket file permissions. On EKS, the CLI runs through `kubectl exec` /
  `docker exec` in any replica; because state is in Valkey, a change made through one replica applies to all.

### 3.1 CLI Command Tree

```text
pivot server  start
pivot client  add | list | remove
pivot token   create | list | revoke | rotate
pivot backend add | list | remove | test
pivot rules   validate | list | test
pivot notifier add | list | remove | test
pivot config  get | set | list
pivot secret  generate | rotate
pivot version
```

`rules test` evaluates a method and path against the active rule set and prints the matching rule, without sending anything to the backend. `rules validate`,
`secret generate` and `version` work without a running server.

The implemented tree departs from that draft in four places, recorded here because the draft is what a reader checks against:

- **`rules apply`** is added. Without it there is no way to install a rule set, and a fresh pivot denies everything — so the drafted `validate | list | test`
  would have described a service that could not be configured. It takes a file, or `--deny-all` for the one rule set that needs no file.
- **`backend` is `show | set | test`**, not `add | list | remove | test`. Backends are not a collection: pivot fronts one origin, and the per-customer part is a
  credential belonging to a client record. So per-client credentials live under `client backend`, where the thing they belong to is.
- **`client` grew `rotate | disable | enable | backend | limit`.** A customer's credentials need rotating, a customer needs suspending without being deleted,
  and the backend credentials and the rate limit each change independently of the rest of the record.
- **`audit` and `cache` are added.** §9.2 requires an audit trail and §10.8 settles that pivot stores the low-volume half of it itself; a trail nothing can read
  is a trail nobody will consult. `cache purge` is what an operator reaches for after narrowing a rule or fixing a route wrongly marked `shared`, and the
  alternative is waiting out a TTL that may be hours.

There is also `outbox status`, for the same reason protean and signpost have one: the outbox is the mechanism behind "nothing lost on restart", and on a
multi-replica deployment it additionally answers whether the queue is stalled because every entry is claimed by a replica that no longer exists.

---

## 4. Request Pipeline

Every request passes the same stages in a fixed order, and any stage can end it. Cheap rejections come first so that denied or abusive traffic never costs a
backend call.

1. **Normalize:** canonicalize the path; reject ambiguous requests with 400. Strip method-override headers.
2. **Token endpoint:** requests to the frontend `auth.path` are answered by pivot itself and never forwarded.
3. **Authenticate:** resolve the client from its pivot credentials; 401 on failure.
4. **Rules:** evaluate method + normalized path against deny, then allow; 403 on deny or no match.
5. **Rate limit:** per-client limit in Valkey; 429 with `Retry-After` when exceeded.
6. **Cache lookup:** serve from cache when the route is cacheable and a valid entry exists.
7. **Coalesce:** identical concurrent requests wait for one backend call.
8. **Backend concurrency limit:** wait for a free slot or fail with 503.
9. **Forward:** send the normalized request with the client's backend credentials; strip the client's own `Authorization` header.
10. **Store and respond:** cache the response if the route allows it, write the audit log entry, emit events.

---

## 5. Path Rules

Rules are static configuration: an allow list and a deny list, each entry a method set plus a glob or RegEx path pattern. Deny is evaluated before allow, and a
request matching neither is denied.

### 5.1 Normalization

Rules are only as strong as the path they match. pivot normalizes before matching and forwards the normalized path, so pivot and the backend's router always see
the same request.

- Percent-decode unreserved characters; reject encoded `/`, `\` and null bytes with 400. An escape of an unreserved character is equivalent to the character
  (RFC 3986 §6.2.2.2), so decoding it loses nothing and makes two spellings compare equal; everything else stays encoded with its hex uppercased, because
  decoding a reserved character would change what the path means.
- Collapse repeated slashes; resolve `.` and `..`; reject paths that climb above the root. Reject a literal backslash too — some routers treat it as a separator
  and pivot does not, which is the same disagreement an encoded one would cause.
- **Drop a trailing slash.** Not in the original draft, and added because the alternative is worse: keeping it leaves two spellings of one route, and the matcher
  then has to decide whether a rule for one covers the other. Covering it widens every allow rule by a path its author did not write; not covering it answers 403
  to a client whose URL differs by one character for reasons nothing in the response explains. Collapsing gives exactly one string per route before any rule sees
  it, and the forwarded path is still the matched path. The trade is a backend that routes `/x` and `/x/` to different handlers, which pivot then cannot
  distinguish — rare, failing towards the canonical form rather than towards more access, and visible in the audit record.
- Strip `X-HTTP-Method-Override` and similar headers.
- Matching is case-sensitive unless a backend declares case-insensitive routing.

### 5.2 Pattern Syntax

- **Glob:** `*` and `?` match within one segment, `**` across segments (including none). Stdlib `path.Match` has no `**`, so pivot ships a small matcher. It
  runs over segments with a dynamic-programming table rather than by recursion: a naive recursive `**` matcher degrades exponentially on a pattern with several
  of them, and the pattern is configuration while the path is attacker-chosen. `***` and a `**` sharing a segment with other characters are refused rather than
  given an invented meaning, as is a pattern ending in `/`, which could never match a normalized path.
- **RegEx:** stdlib `regexp` (RE2), anchored automatically at both ends. Linear-time matching, so configured patterns cannot cause ReDoS. Anchoring is not a
  convenience: unanchored, `/api/product` would match `/evil/api/product`, and a deny rule would be sidestepped by a prefix.
- Each entry declares its kind explicitly; no guessing from the pattern string.
- Matching is whole-path. There is no partial match, because a rule matching a prefix would allow everything beneath it by accident.

### 5.3 Draft Configuration

```yaml
rules:
  deny:
    - { methods: ["*"], glob: "/api/_action/**" }
    - { methods: ["*"], glob: "/api/oauth/**" }
    - { methods: ["*"], glob: "/api/search/customer*" }
  allow:
    - { methods: [GET], regex: "/api/[a-z0-9-]+(/[0-9a-f]{32})?" }
    - { methods: [POST], glob: "/api/search/*" }
    - { methods: [POST], glob: "/api/search-ids/*" }
```

> [!NOTE] The schema is generated, not maintained
> `docs/schema/pivot-rules-v1.json` is produced from the Go types that compile the document, so it cannot drift from them — a test fails if the committed file
> and the generated one differ. It exists for the same reason signpost's manifest schema does: a rule set is a document somebody writes by hand, and the
> mistakes worth catching while it is being written are the ones an editor can catch. It describes a well-formed document only; whether a regex compiles as RE2,
> whether the whole document is within `MaxRules`, and how a per-client set accumulates onto the global one stay in Go, which is what `rules validate` runs.
> The two are kept in agreement by tests that check the schema's method and glob constraints against the compiler's verdict on the same input.

### 5.4 Shopware Example Rule Set

Read-only, as drafted above, and published as a **documented example** at `docs/examples/pivot/shopware-readonly.yaml` rather than shipped in the binary.
**pivot installs nothing.** A fresh instance denies everything and reports itself not ready until an operator applies a document they have read.

That is a change from the first implementation, which carried this rule set as a `--preset` compiled into the binary. A rule set is a statement about what one
installation will serve, so one inside the binary is a statement nobody reviewed that a single command applies — and the convenience was worth less than the
review. `rules apply` takes a file; `--deny-all` is the one rule set that needs none, because the moment an operator reaches for it is an incident.

Shopware is the reference backend and the first to be guarded, not the focus: §2 says a backend is a rule set plus auth configuration, and nothing in pivot
itself knows what Shopware is. The example adds two denies to the draft — `/api/search-ids/customer*`, which is the id variant of the customer search, and
`/api/_info/**`, which enumerates entities, routes and the installed version — and carries the reason for every deny in a `comment` field that appears in
`rules list` and in the audit entry of a request the rule decided. A deny rule without a stated reason is a rule the next operator deletes.

Being a file rather than a constant does not make it unverified: the rules package compiles every example in `docs/examples/pivot/`, asserts this one's
headline behaviour, and the end-to-end suite applies this very file against a backend speaking the Admin API's shapes — which is what §10.6 rests on.

> [!WARNING] Why `/api/_action/**` is denied entirely
> Several of those routes have had missing ACL checks — order state transitions ([CVE-2026-48014](https://osv.dev/vulnerability/CVE-2026-48014)), the Sync API
> ([CVE-2026-48008](https://github.com/advisories/GHSA-gv8p-48fr-4fxg)) and version routes ([issue #20828](https://github.com/shopware/shopware/issues/20828)).
> The blanket deny is a response to a demonstrated pattern, not a precaution.

> [!CAUTION] Deny rules cover direct routes only
> Data reachable through associations of an allowed entity — customer data on an order search, for instance — is controlled by the backend ACL alone. No path
> rule can see it. This is the concrete reason the second layer (§1) is not optional.

---

## 6. Authentication

Authentication has two independent sides, each with its own `auth.mode` and `auth.path`. Customers only ever hold pivot credentials; backend credentials never
leave pivot.

| Side     | Purpose                                | Modes                                                           |
| -------- | -------------------------------------- | --------------------------------------------------------------- |
| Frontend | How customers authenticate to pivot    | `oauth2` (client credentials emulation), `http-basic`, `bearer` |
| Backend  | How pivot authenticates to the backend | `oauth2` (client credentials), `http-basic`, `api-key` (header) |

### 6.1 Frontend

- In `oauth2` mode, pivot answers `POST <auth.path>` (Shopware: `/api/oauth/token`) itself, with the same response shape as the backend. Existing Shopware
  clients work unchanged.
- Client IDs and secrets are random, shown once, stored as SHA-256 hashes in Valkey.
- Issued access tokens are opaque, short-lived, stored hashed with their expiry in Valkey, and revocable immediately.

### 6.2 Backend

- Each pivot client maps to its own backend credentials. For Shopware: one integration per customer with a restricted ACL role.
- In `oauth2` mode, a token manager fetches and refreshes backend tokens before expiry and shares them across replicas through Valkey.
- Backend credentials are stored encrypted (see §8).

### 6.3 Draft Configuration

```yaml
backend:
  url: https://shop.internal.example
  auth:
    mode: oauth2
    path: /api/oauth/token
frontend:
  auth:
    mode: oauth2
    path: /api/oauth/token
```

---

## 7. Load Protection & Caching

Per-client rate limits keep customers fair to each other; the backend concurrency limit is what actually protects production. pivot enforces both.

### 7.1 Limits

| Mechanism          | Scope                    | State                           | Purpose                                            |
| ------------------ | ------------------------ | ------------------------------- | -------------------------------------------------- |
| Rate limit         | Per client               | Valkey (shared across replicas) | Fairness, abuse protection                         |
| Concurrency limit  | Per backend, per replica | In memory                       | Cap simultaneous backend calls                     |
| Request coalescing | Per replica              | In memory                       | One backend call for identical concurrent requests |

The rate limit is a token bucket; see §10.5 for the algorithm and why it is shared across replicas rather than per replica. The other two are deliberately per
replica: coordinating either through Valkey would put a round trip on the hot path to discover something true only for the duration of one backend request.

Coalescing keys on the **cache key**, which already covers the client, the method, the normalized path, the canonical query and a hash of the body. Anything
coarser would let two customers share a response, so it reuses the one string already known to identify a request completely. A follower that gives up does not
cancel the call it was waiting on — another follower may still want it, and one client disconnecting is not a reason to waste a backend request in progress.

Both limiters report their state through `config view`: slots full with nothing waiting is a well-sized limit, slots full with a queue is one that needs raising
or a backend that needs attention.

> [!IMPORTANT] The concurrency limit multiplies by replica count
> It is enforced per replica, so the effective backend limit is the configured value **× replica count**. This is documented rather than synchronized through
> Valkey, to keep the hot path free of extra round trips — which means scaling out silently raises the load ceiling on production unless the configured value is
> lowered to match.

### 7.2 Cache

- Only routes explicitly marked cacheable are cached, with a TTL per route.
- `GET` and allowed `POST` search requests are cacheable; the key covers the normalized path, canonical query string and a hash of the canonicalized body.
- The key always includes the client scope. A route can be marked `shared` to drop the scope, only when its response is identical for all clients.
- Backend `Cache-Control: no-store` and `private` are honoured.

### 7.3 Optional Cache Encryption

Encryption of cached responses is a per-route flag, off by default. The operator enables it on routes that can return personal data.

```yaml
routes:
  - { glob: "/api/search/product", cache: { ttl: 5m } }
  - { glob: "/api/search/order", cache: { ttl: 1m, encrypt: true } }
```

> [!CAUTION] pivot cannot work out which routes need this
> A route's path does not reveal whether its responses carry personal data: associations can pull personal data into otherwise harmless searches. The flag is
> therefore an operator judgement per route, and the default (off) is the unsafe direction for anything touching customer data.

---

## 8. State, Secrets & Notifications

All state lives in Valkey; pivot replicas hold nothing that cannot be lost. Badger is not used.

| Data                                | Stored as                        |
| ----------------------------------- | -------------------------------- |
| Client IDs and secrets              | SHA-256 hash                     |
| Issued access tokens                | SHA-256 hash with TTL            |
| Backend credentials, backend tokens | AES-GCM encrypted                |
| Notifier credentials                | AES-GCM encrypted                |
| Rate-limit counters                 | Plain, with TTL                  |
| Cached responses                    | Plain, or AES-GCM per route flag |
| Notification outbox                 | Plain                            |

Valkey has no native encryption at rest, so pivot encrypts sensitive values itself before writing them.

### 8.1 `PIVOT_SECRET`

Same scheme as [[protean]] and [[signpost]]: one high-entropy secret of at least 32 bytes, `pivot secret generate` to create it, keys derived with `crypto/hkdf`
and SHA-256 per purpose (`pivot/credential-encryption`, `pivot/cache-encryption`, `pivot/webhook-signing`). **All replicas must share the same secret.**

### 8.2 Shared Packages

`pkg/kv` is an interface with a Badger implementation (protean, signpost) and a Valkey implementation (pivot). `pkg/secret`, `pkg/event`, `pkg/notify` and
`pkg/forwarded` are reused unchanged.

`pkg/kv/valkeykv` landed on 2026-10-11, ahead of the rest of pivot, since it was the one piece every other part of this document depends on. The client library
is `valkey-io/valkey-go`; see §10.10 for why, and for the two behaviours it had to be made to share with the Badger store.

> [!NOTE] Resolved: the interface and the race fix landed together in Phase 0
> Both changes were sequenced as one, as this section asked. `pkg/kv` holds the interface only; implementations are subpackages (`pkg/kv/badgerkv`,
> `pkg/kv/valkeykv`) so the protean and signpost binaries never link a Valkey client. See [[protean]] §10.4 for the full record.
>
> Three things pivot should know before the Valkey implementation is written:
>
> - **`pkg/kv/kvtest` is a conformance suite, and passing it is the definition of being a `kv.Store`.** It pins the awkward cases — an empty value counts as
>   present, deleting an absent key succeeds, `Increment` over a non-numeric value is `kv.ErrNotAnInteger` — so the Valkey store cannot drift from the Badger
>   one. The Badger implementation runs it three times: on disk, in memory, and encrypted.
> - **The atomic primitives pivot needs are already in the interface.** `Increment` for rate limiting (§7.1), `SetIfAbsent` for token issuance (§6.1), and
>   `CompareAndSwap` as the generic primitive an outbox claim (§10.4) can be built on. `Increment` stores its value as decimal ASCII specifically so Valkey can
>   use `INCRBY` natively.
> - **`Keys` and `Scan` are expensive on Valkey and must stay off the request path.** They are documented as unordered for the same reason: `SCAN` guarantees
>   no ordering, so no caller may rely on Badger's.
>
> A general multi-key transaction was deliberately left out, since Badger transactions and Valkey MULTI/Lua do not abstract cleanly and nothing documented
> needs one. If the outbox claim mechanism (§10.4) turns out to need more than `CompareAndSwap`, that is the decision to revisit.

### 8.3 Events

| Event                 | Trigger                                                       |
| --------------------- | ------------------------------------------------------------- |
| `client.auth_failed`  | Repeated failed authentication for a client or source address |
| `rule.denied`         | Request denied by a rule (aggregated)                         |
| `client.rate_limited` | Client exceeded its limit (aggregated)                        |
| `backend.failed`      | Backend errors or timeouts above threshold                    |
| `backend.auth_failed` | Backend rejected pivot's credentials                          |

---

## 9. Security, Compliance & Platform Support

Linux is the only supported platform; no Windows binaries are shipped.

> [!IMPORTANT] pivot bounds the damage; it does not fix the backend
> It reduces the blast radius of a misconfigured backend permission but cannot compensate for one: a customer granted too many backend permissions on an allowed
> route gets that data. And the backend must not be reachable by customers directly — otherwise pivot is simply bypassed.

### 9.1 Security Model

| Surface   | Exposure                      | Protection                                             |
| --------- | ----------------------------- | ------------------------------------------------------ |
| Proxy     | Network, HTTPS                | pivot client credentials, path rules, rate limit       |
| Backend   | Internal network only         | Per-customer backend credentials and permissions       |
| Admin API | Local Unix socket per replica | Socket file permissions                                |
| Valkey    | Internal network only         | Valkey auth + TLS, sensitive values encrypted by pivot |

### 9.2 ISO 27001 Notes

- Per-request audit log: client, method, normalized path, matched rule, status, latency, timestamp. No request or response bodies.
- Administrative actions through the CLI are logged separately.
- Key management for `PIVOT_SECRET` maps to A.8.24 Cryptography.

### 9.3 GDPR

The audit log contains client source addresses and the cache may contain personal data. Both get configurable retention (log) and TTLs (cache). Encrypting
cached personal data is the operator's choice per route (§7.3).

---

## 10. Open Questions & Verification Items

Items keep their original number for the life of the document, so a cross-reference stays valid after an item is resolved. They are headings rather than a
numbered list because Prettier, which is authoritative for Markdown here, renumbers ordered lists.

### 10.1 Does any customer need write access? — ✅ resolved 2026-10-11

**No, and never.** pivot is an edge service deployed at the perimeter of a production application to shield it from direct customer traffic; restricting the
paths to reads is the reason it exists. Confirmed by Max on 2026-10-11 as a permanent property, not a current state.

That makes it worth enforcing structurally rather than through configuration. `rules.ForwardableMethods` is `GET`, `HEAD`, `POST` and nothing else:

- The pipeline checks the method **before** consulting the rules, so a `PUT`, `PATCH`, `DELETE`, `CONNECT` or `TRACE` is refused whatever rule set is loaded.
  There is no global rule, no per-client rule and no setting that can put a write through.
- A rule naming a write method is a **compile error**, so the mistake surfaces at `rules validate` or `rules apply` rather than at the request that would have
  used it.

`POST` is forwardable because a read is not always a `GET` — the Shopware search API, and plenty of others, take their query in a POST body. It is in the set of
_forwardable_ methods, not of permitted ones: deny-by-default still means a POST reaches the backend only through an explicit allow rule, and the Shopware example
allows it on `/api/search/*` and `/api/search-ids/*` only.

> [!NOTE] A wildcard method is accepted on a deny rule and refused on an allow rule
> "Deny every method on this path" is a complete statement an author can mean. "Allow every method on this path", in a deny-by-default security configuration, is
> a shorthand nobody re-reads — so pivot makes the author name `GET` or `POST` and the rule then says what it grants.

### 10.2 Global or per-client rules — ✅ resolved 2026-10-11

Both: one global rule set plus optional per-client additions, combined **accumulatively**. The deny lists are concatenated and the allow lists are concatenated,
then evaluated deny-first as §2 specifies. So a client's rules can grant a path the global set does not, and can add restrictions of their own.

A per-client rule **cannot** reopen a path the global deny list refuses. Max asked whether that override would be useful and left the call to implementation; it
is deliberately not offered, and the reason is auditability rather than complexity. The global deny list is the reviewed statement of what this instance will
never serve, and an override makes that statement conditional on a per-customer record nobody re-reads — the failure is silent, affects one customer, and is
invisible in the global list. With accumulation only, "what can this customer reach" is answered by reading two lists under a fixed precedence.

An operator who genuinely needs an exception narrows the global deny and adds the broader restriction to the other clients. That is more typing and it leaves the
intent visible in the configuration instead of buried in a flag.

Global denies are evaluated before client denies. It makes no difference to the verdict — either match denies — but it means the audit entry names the global
rule when both match, which is the one an operator cannot change per client and therefore the one worth seeing.

Cache routes (§7.2) go the other way: a client route overrides the global TTL for its path. Caching is not an access-control decision — the rules have already
allowed the request by the time a route is consulted — so first-match-wins costs nothing and lets an operator shorten one customer's TTL without touching the
global set.

### 10.3 Rule reload — ✅ resolved 2026-10-12

Hot reload across replicas. A version counter in Valkey is authoritative and a pub/sub announcement is an optimisation on top of it, which is the only
arrangement that converges.

Each replica holds a compiled `RuleTable` behind an `atomic.Pointer` — the same arrangement signpost uses for its route table, for the same reason: a request
must never see a rule set that is half-updated, because the half it saw might be the half without the deny. Any administrative change bumps one integer and
publishes it; every replica subscribes to the channel and also polls that integer every fifteen seconds.

The poll is not a fallback nobody needs. Valkey pub/sub is fire-and-forget, so a replica reconnecting when a change is announced never hears it and would serve
the old rule set indefinitely. The counter is what guarantees convergence; the announcement is what makes it take milliseconds instead of seconds. A test
asserts both paths: one that drives the rebuild directly, and one that leaves polling off entirely so only the announcement can have delivered the change.

One counter covers rules, clients and settings rather than one per thing. A replica only needs to know that _something_ moved, and reading one integer is the
cheap question — a rebuild reads every client record, which on an instance with hundreds of customers would be a steady load on Valkey if it ran unconditionally
every fifteen seconds.

Two failure behaviours worth recording:

- A rule set that does not compile is **never stored**. Storing one would be worse than refusing it: every replica would fail its next reload and keep serving
  whatever it had, which is a configuration change that appears to have worked and did not.
- One client's uncompilable rules do not stop the table rebuilding. That client falls back to the global set — the restrictive direction — and the log says so.
  The alternative is every other customer serving from a stale set because one record is wrong.

The replica that made the change reloads immediately rather than waiting for its own announcement, so an operator who changes a rule and then tests it through
the same replica sees the new behaviour.

### 10.4 Outbox delivery across replicas — ✅ resolved 2026-10-12

Built as predicted, on `kv.CompareAndSwap`, with the lease the prediction flagged as the missing piece. No Valkey streams and no addition to the store
interface, so §8.2's narrow interface holds.

A pending entry carries an optional claim — a holder and an expiry. Claiming is a compare-and-swap against the bytes the entry held when it was read, so two
replicas cannot both come away believing they hold the same entry; the loser is told it lost and moves to the next one. A test races four holders against twenty
entries and requires each entry to be claimed exactly once.

The lease is what makes a dead replica recoverable, which is the case a claim without one cannot handle: the entry would sit claimed forever and its
notification would never be sent, the precise failure a persistent outbox exists to prevent. An expired lease is claimable by anyone, and a holder re-claiming
its own entry renews rather than loses it.

Three behaviours are worth stating because they are where the design could have gone wrong:

1. A failed attempt **drops** the claim. This replica is finished with the entry whatever happens next, and whichever replica is free when the backoff elapses
   should retry — holding the claim across the wait would pin the retry to a process that may be gone.
2. A pass cut short by shutdown **releases** the entries it had claimed but not reached, so a rolling deployment does not leave a batch unclaimable for the rest
   of its lease.
3. protean and signpost pass no holder, so their delivery loop reads the queue with `Pending` and claims nothing — exactly as before. One process cannot
   duplicate a notification with itself, so the bookkeeping would buy nothing and cost a compare-and-swap per entry.

> [!NOTE] The duplicate direction is unchanged, and deliberate
> Delivery stays at-least-once. A lease that expires while its holder is in fact still working — a very slow SMTP relay — produces a duplicate notification
> rather than a lost one. That is the same trade the outbox already makes by marking an entry delivered after the send rather than before, and it is the right
> way round: a duplicate alert is a nuisance, a missing one is a fault.

### 10.5 Rate-limit algorithm — ✅ resolved 2026-10-11

**Token bucket**, implemented as a Lua script through `valkeykv.Store.Client`.

Max's reasoning, which the implementation follows: pivot proxies, so a short burst costs the backend a handful of requests it can absorb, and the per-replica
concurrency limit (§7.1) is what actually protects production from volume. A sliding window would refuse a client's third request in a second even with the
backend idle, which for an API whose clients page through results in bursts is a limiter that fights normal use. The bucket's capacity is the burst a client may
take at once and the rate is what it may sustain; a fractional rate is meaningful, so `0.5` is one request every two seconds.

The refill, the check and the write happen inside one script execution, which is the property that matters: two replicas checking the same client concurrently
cannot both see the same token and both take it. A read-then-write would allow that, and the limit would be approximately rather than actually enforced — a test
races a hundred callers against a capacity of twenty and requires exactly twenty through.

The refill is computed from elapsed time rather than driven by a timer, so there is no background process to keep running and a bucket nobody touched for an hour
is indistinguishable from one refilled all along. A clock that goes backwards is clamped to zero elapsed rather than subtracting tokens: replicas' clocks differ
by milliseconds, and a limiter that punished a client for reaching the replica with the slower clock would be unexplainable from outside.

Two defaults are the safe direction rather than the strict one. A zero capacity means _unlimited_, so a client record written before limits were configured does
not silently stop working — a limiter that failed closed on a missing number would take a customer offline for a configuration gap. And `Retry-After` has a
one-second floor, because it travels in whole seconds and a sub-second delay would round to zero and invite an immediate retry that fails again.

This is the reason `valkeykv.PhysicalKey` is exported. §8.2 kept the store interface narrow and noted that a token bucket would need a script or an interface
addition; the script is the smaller change, and that helper is what keeps its keys the ones the store itself would use rather than a second key format free to
drift.

> [!NOTE] The one-second TTL granularity does not bite here
> [[protean]] §10.4 records that a `kv.WithTTL` TTL is a lower bound honoured to one second, so a sub-second window is not expressible through the interface. The
> bucket does not use `kv.WithTTL`: it stores its state as a hash with `PEXPIRE`, and the expiry only has to outlive the refill window rather than mark it. The
> window itself is arithmetic on millisecond timestamps.

### 10.6 Verify the Shopware default rule set — ✅ resolved 2026-10-12, within its limits

Verified behaviourally, against a backend speaking the Admin API's shapes, in `tests/e2e/pivot`. Not verified against an enumerated route list, and the
difference matters enough to state plainly.

What the end-to-end test establishes: the `shopware-readonly` example denies `/api/_action/**`, `/api/oauth/**`, the customer searches and `/api/_info/**`;
allows entity reads and the `search` and `search-ids` endpoints; and that every spelling of a denied path — repeated slashes, dot segments, a percent-encoded
letter — still reaches the deny, while an encoded separator is refused before any rule is consulted. It runs the real binary, two replicas, a real Valkey from
testcontainers, and configures everything through the CLI an operator would type.

What it does not establish: that the allow list is _exhaustive_ against a given Shopware version's routes. Doing that needs a deployed Shopware and its
database, and it would be a check that goes stale with every Shopware release. The honest position is the one §1 already takes — the rules are the first of two
layers, and the second is the per-customer backend ACL. An allow rule that turns out to be broader than intended is bounded by the integration's own
permissions, which is exactly why that second layer is not optional.

Max's steer on 2026-10-12 was not to over-focus on Shopware: it is the reference backend and the first to be guarded, not the point. So the same test covers the
`api-key` and `http-basic` backend modes, which no Shopware deployment would exercise at all, and `rules.PresetDocument` is the only place in the codebase that
knows what Shopware is.

> [!NOTE] Three additions to the draft rule set, each with a reason in the rule
> `/api/search-ids/customer*` is the id variant of the customer search and was missing. `/api/_info/**` enumerates entities, routes and the installed version,
> which is reconnaissance rather than data a customer needs. And every deny carries its reason in a `comment` field that reaches `rules list`, `rules test` and
> the audit record — a deny rule without a stated reason is a rule the next operator deletes.

### 10.7 TLS termination — ✅ resolved 2026-10-06

Decided once for all three services. Both modes are supported and selected by configuration: native TLS from operator-supplied certificate and key files, or
plain HTTP behind a reverse proxy — which on EKS is the ingress. ACME is **not** implemented. See [[protean]] §4.1 for the mechanics and §10.5 for the decision
record.

pivot is the service where the proxy mode is the expected deployment, and also the one where `trusted_proxies` matters most: the client source address feeds the
per-client rate limiter (§7.1), the `client.auth_failed` and `client.rate_limited` events (§8.3), and the audit log (§9.2). An over-broad `trusted_proxies` lets a
customer set its own apparent source address.

> [!CAUTION] Path normalization happens before rule matching, and TLS mode must not change the path
> §5.1 depends on pivot and the backend's router seeing the same request. A reverse proxy that rewrites or re-encodes the path before pivot sees it reintroduces
> exactly the second interpretation that §2 exists to eliminate. In proxy mode the ingress must be configured to pass the path through unmodified.

### 10.8 Audit-log retention defaults — ✅ resolved 2026-10-12

**Ninety days**, as Max asked for, enforced by a TTL on the records pivot stores itself.

One correction to the framing, since §9.2 makes this a compliance artefact: there is no statutory maximum of ninety days under GDPR. Art. 5(1)(e) is a necessity
and proportionality test rather than a number. So ninety days is recorded here as a defensible proportionate period, not as "the legal limit" — it matches
protean's address-history default, which keeps one answer to "how long does netory keep things" across the three services, and an operator with a different
obligation sets a different value.

What makes the promise real is a split, because §9.2 asks for two things with very different volumes:

- The **per-request** audit log — client, method, normalized path, matched rule, status, latency — is one record per request, so it goes to the structured log
  where the operator's pipeline handles the volume and the retention. pivot cannot enforce a period on records that leave the process, and signpost §9.7 records
  the same conclusion.
- **Administrative actions and aggregated security outcomes** are low-volume, so pivot stores those itself, in Valkey, with the retention as a `kv` TTL. The
  ninety days is therefore enforced by the store rather than asserted in a document, and any replica can answer "what happened to this customer three weeks ago"
  without a log search.

A retention of zero means pivot keeps nothing of its own; the log line still goes out, so the record is not lost — it is simply not pivot's to hold.

Client addresses get the same treatment as signpost's (§9.7 there): `accesslog.client_address` is `full`, `anonymised` or `off`, defaulting to **anonymised** —
IPv4 to a `/24`, IPv6 to a `/48`. The reduction happens where the record is built, before it reaches any handler, because a record that has left that function
carrying a full address cannot be un-sent. An unrecognised stored value is treated as `off` rather than `full`, so a settings document from a future version
cannot make this build record more than it knows it agreed to.

### 10.9 The `pkg/kv` namespace race — ✅ resolved in Phase 0, and the Valkey store now meets its criterion

Resolved together with the store interface, as §8.2 asked. See the note there and [[protean]] §10.4 for the full record. The Valkey implementation's acceptance
criterion was `pkg/kv/kvtest` passing under `--config=race`, and as of 2026-10-11 it does: all 21 subtests, against a real Valkey 8.1.10, including the four
concurrency ones.

Against a real server rather than a fake, deliberately. The half of this contract worth testing is the server's behaviour and not ours — what `SET NX` answers
for a key that exists, whether `SCAN` yields a key that has expired, what `INCRBY` says about a non-numeric value — and a fake would only establish that the
fake agrees with itself. The suite skips itself with instructions when no Valkey is reachable, so a developer working on protean sees no red; CI runs a Valkey
service container and sets `VALKEY_TEST_ADDR`, because a suite that always skips is not a gate.

### 10.10 Valkey client library — ✅ resolved 2026-10-11

[`github.com/valkey-io/valkey-go`](https://github.com/valkey-io/valkey-go), Apache-2.0, the Valkey project's own client. Signed off before it was added.

The Valkey project lists **two** official Go clients, and the second one settles the question rather than complicating it. Valkey GLIDE's Go binding is cgo
linking a prebuilt Rust static library — its `base_client.go` opens with `#cgo LDFLAGS: -lglide_ffi` and a per-platform `rustbin` search path. netory registers no
C toolchain for first-party code and ships statically linked binaries built with `--config=release`, which forces `CGO_ENABLED=0`, so GLIDE is not a candidate
here whatever its merits. `valkey-go` is pure Go: it builds under `CGO_ENABLED=0` and the only module it adds beyond itself is `golang.org/x/sys`, which this
repo already carried.

It is also the better fit on its own terms. It does automatic pipelining, which matters for a service whose hottest path is a rate-limit counter, and it exposes
`SET NX`, `INCRBY` and Lua as first-class commands — the three primitives §8.2 says the interface needs. Server-assisted client-side caching is its headline
feature and `pkg/kv/valkeykv` deliberately does not use it: every value in this store is state whose purpose is to be shared and current across replicas, and a
cached read of a rate-limit counter is a rate limit that does not limit. The option is wired through for a caller that one day wants it, and is off by default
so the store still connects to a server or proxy without `CLIENT TRACKING`.

> [!NOTE] What the implementation had to add on top
> Valkey has no native compare-and-swap, so `CompareAndSwap` is a Lua script: the compare and the write happen in one server-side execution with nothing able to
> interleave. `WATCH`/`MULTI` would also work and would be worse, because per-connection watch state on a pool shared by many goroutines is a thing to reason
> about and a script has none. `Increment` is `INCRBY` with its expiry applied inside the same script rather than by a second command — a window counter whose
> TTL is set separately exists for a moment without one, and a crash in that moment leaves a client rate-limited forever.
>
> Two agreements with the Badger store are not visible from either implementation alone, so they are written down here. A write with no TTL **clears** any
> expiry the key already had, because that is what a Badger entry with no `ExpiresAt` does — hence the `PERSIST` on the no-TTL path of the increment script. And
> both backends resolve a TTL through `kv.ExpiresAt`, even though Valkey's `PXAT` could express the exact duration, so that a key expires at the same moment
> whichever store holds it.
