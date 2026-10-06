# pivot

Transparent API proxy. It sits between customers and a production API: it issues its own
credentials, authenticates to the backend on the customer's behalf, filters requests by path rules,
and protects the backend with rate limits, a concurrency cap and a response cache.

Customers use the backend's own API documentation and their existing clients. pivot is invisible to
them.

The constraint that drives the design: **two independent layers must both fail before a customer
reaches data they should not see.** pivot's path rules are the first; the backend permissions of
that customer's own backend credentials are the second. Neither is trusted to be sufficient alone.

**pivot is read-only by construction.** It forwards `GET`, `HEAD` and `POST` and nothing else, and
no rule set can change that.

For scope, architecture and the reasoning, read [`docs/design/pivot.md`](../../docs/design/pivot.md). This file
is how to run it.

## Quick start

```sh
# 1. Generate a secret. Every replica needs the same one: keys derived from it
#    decrypt the backend credentials in Valkey, so a replica with a different
#    secret starts cleanly and then fails every forward leg.
install -d -m 0700 /etc/pivot
pivot secret generate > /etc/pivot/secret
chmod 0600 /etc/pivot/secret

# 2. Start a replica. Several may run at once; there is no lock to take.
export PIVOT_SECRET_FILE=/etc/pivot/secret
pivot server start \
  --listen :8443 \
  --valkey valkey.internal:6379 \
  --trusted-proxies 10.0.0.0/8

# 3. Configure it. A fresh pivot denies everything, so this is not optional.
#    pivot ships no rule set; copy one of the examples below and read it first.
curl -fsSLO https://raw.githubusercontent.com/adnoctem/netory/main/docs/examples/pivot/shopware-readonly.yaml
pivot rules validate ./shopware-readonly.yaml
pivot rules apply ./shopware-readonly.yaml
pivot backend set https://shop.internal.example

# 4. Onboard a customer.
pivot client add 'Acme GmbH' \
  --backend-mode oauth2 \
  --backend-client-id "$SW_INTEGRATION_ID" \
  --backend-client-secret "$SW_INTEGRATION_SECRET" \
  --burst 60 --per-second 2
```

The client secret is printed once and stored only as a SHA-256 hash. A lost secret is rotated, not
retrieved.

## What the customer does

Nothing unusual. In the default `oauth2` mode pivot answers the backend's own token endpoint shape,
so an existing client works unchanged against the backend's documentation:

```sh
TOKEN=$(curl -s -X POST https://pivot.example.org/api/oauth/token \
  -d grant_type=client_credentials \
  -d "client_id=$PIVOT_CLIENT_ID" \
  -d "client_secret=$PIVOT_CLIENT_SECRET" | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" https://pivot.example.org/api/product
```

The response is the backend's, byte for byte, plus two headers a client could not otherwise know:
`X-Pivot-Cache` (`hit`, `miss` or `bypass`) and `X-RateLimit-Remaining`.

Two other frontend modes exist, set with `pivot config set frontend.auth_mode`:

| Mode         | What the customer sends                                  |
| ------------ | -------------------------------------------------------- |
| `oauth2`     | A token from pivot's emulated token endpoint (default)   |
| `bearer`     | A long-lived token issued with `pivot token create`      |
| `http-basic` | The client id and secret directly, with no exchange step |

## Rules

Rules are an allow list and a deny list over method plus normalized path. **Deny is evaluated first,
and a request matching neither is denied** — a missing rule is never an implicit permission.

```yaml
rules:
  deny:
    - methods: ["*"]
      glob: /api/_action/**
      comment: several _action routes have shipped with missing ACL checks
  allow:
    - methods: [GET]
      regex: /api/[a-z0-9-]+(/[0-9a-f]{32})?
      comment: read one entity collection, or one entity by its id
    - methods: [POST]
      glob: /api/search/*
      comment: the search API takes its query in a POST body, so this is a read
routes:
  - methods: [POST]
    glob: /api/search/product
    cache: { ttl: 5m }
  - methods: [POST]
    glob: /api/search/order
    cache: { ttl: 1m, encrypt: true }
```

```sh
pivot rules validate ./rules.yaml   # works with no server; this is the CI check
pivot rules apply ./rules.yaml
pivot rules list
pivot rules test /api/_action/order/state
```

`rules test` is the command to reach for when a customer reports a 403. It prints the normalized
path, the verdict, and the rule that decided — including that rule's `comment`, which is why every
deny in the documented examples carries one.

A JSON Schema for the rule document is published at
[`docs/schema/pivot-rules-v1.json`](../../docs/schema/pivot-rules-v1.json). Point your editor at it
for completion and inline errors while writing a rule set:

```yaml
# yaml-language-server: $schema=../../docs/schema/pivot-rules-v1.json
```

It is generated from the Go types that compile the document, so the two cannot drift — a test fails
if the committed file and the generated one differ. It catches what it can while you type: an
unknown key, a method pivot never forwards, the method wildcard on an allow rule, a rule with both a
glob and a regex or with neither, a glob that is not absolute or ends in a slash, a `**` that is not
a whole segment.

What it cannot catch is why `rules validate` still exists: whether a regex compiles as RE2, whether
the document's total entry count is within the limit — JSON Schema cannot add two array lengths —
and how a per-client set accumulates onto the global one. A document that satisfies the schema is
well-formed, not necessarily one pivot will accept.

> [!NOTE] `ttl` is spelled differently in YAML and JSON
> In YAML it is a duration string (`ttl: 1m`). In JSON it is an integer count of nanoseconds, which
> is how Go encodes a duration, so `"ttl": "1m"` in a JSON document is rejected by the decoder. The
> schema accepts both forms because it cannot tell which encoding it is being applied to.

### Patterns

| Kind    | Syntax                                                                |
| ------- | --------------------------------------------------------------------- |
| `glob`  | `*` and `?` within one segment, `**` across segments (including none) |
| `regex` | Go `regexp` (RE2), anchored at both ends automatically                |

Each entry declares its kind; nothing is guessed from the pattern. Matching is whole-path — a rule
matching a prefix would allow everything beneath it by accident. A regex is anchored whether or not
its author anchored it, because unanchored `/api/product` matches `/evil/api/product`.

A `*` in a method list is accepted on a **deny** rule and refused on an **allow** rule. "Deny every
method on this path" is a complete statement; "allow every method" in a deny-by-default
configuration is a shorthand nobody re-reads, so pivot makes the author name `GET` or `POST`.

A rule naming `PUT`, `PATCH` or `DELETE` does not compile. There is no configuration that grants a
write.

### Example rule sets

**pivot ships no rule set and installs nothing.** A fresh instance denies everything and reports
itself not ready until an operator applies a document. What used to be a `--preset` is now a file in
this repository, because a rule set is a statement about what one installation will serve, and one
compiled into the binary is a statement nobody reviewed that a single command applies.

| Example                                                                      | What it is                                                             |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| [`shopware-readonly.yaml`](../../docs/examples/pivot/shopware-readonly.yaml) | A complete read-only rule set for the Shopware 6 Admin API             |
| [`deny-all.yaml`](../../docs/examples/pivot/deny-all.yaml)                   | Permits nothing: the starting point for a backend with no example here |

```sh
# Copy it, read it, change what your installation needs, then apply it.
pivot rules validate ./shopware-readonly.yaml   # no server needed
pivot rules apply ./shopware-readonly.yaml

# Or turn an instance off without stopping it, with no file involved.
pivot rules apply --deny-all
```

Read the denials before trusting the Shopware example. They are judgements about one installation's
data, and yours may hold personal data behind a path the example allows. Shopware is the reference
backend rather than the point — nothing in pivot itself knows what Shopware is, and the `api-key`
and `http-basic` backend modes exist for backends that are not it.

Both examples are compiled by pivot's own test suite, and the Shopware one is applied by the
end-to-end suite against a backend speaking the Admin API's shapes, so neither can rot into
something that no longer loads.

### Per-customer rules

```sh
pivot rules apply ./acme-extra.yaml --client <client-id>
```

Per-client rules **accumulate** with the global set: they can grant a path the global set does not,
and can add restrictions of their own. They **cannot** reopen a path the global deny list refuses.

That is deliberate rather than a limitation. The global deny list is the reviewed statement of what
this instance will never serve, and a per-customer exception would make it conditional on a record
nobody re-reads — the failure would be silent, affect one customer, and be invisible in the global
list. With accumulation only, "what can this customer reach" is answered by reading two lists under
a fixed precedence. An operator who genuinely needs an exception narrows the global deny and adds
the broader restriction to the other clients, which leaves the intent in the configuration.

### Path normalization

pivot canonicalizes a path before matching and forwards the canonical form, so pivot and the
backend's router always see the same request. A rule is only as strong as the path it matched.

- Escapes of unreserved characters are decoded; everything else stays encoded with its hex
  uppercased. An encoded `/`, `\` or NUL is **refused with 400**, never decoded.
- Repeated slashes collapse; `.` and `..` resolve; a path climbing above the root is refused.
- A trailing slash is dropped, so one route has exactly one spelling.
- `X-HTTP-Method-Override` and friends are stripped.

The consequence worth knowing: `/api/v1/../_action/order` is denied by a rule for `/api/_action/**`,
and `/api%2F_action/order` is refused outright rather than guessed at.

## Load protection

| Mechanism          | Scope                    | Where the state lives          |
| ------------------ | ------------------------ | ------------------------------ |
| Rate limit         | Per client               | Valkey, shared across replicas |
| Concurrency limit  | Per backend, per replica | In memory                      |
| Request coalescing | Per replica              | In memory                      |

```sh
pivot client limit <client-id> --burst 60 --per-second 2
pivot config set ratelimit.default_burst 30
pivot config set backend.concurrency 16
```

The rate limit is a **token bucket**: `--burst` is what a client may take at once, `--per-second`
what it may sustain. A fractional rate is meaningful, so `0.5` is one request every two seconds. It
is shared across replicas, so a customer's allowance is its whole allowance however many replicas
serve it.

A zero burst means **unlimited**, not zero. A client record written before limits were configured
must not silently stop working.

> [!IMPORTANT] The concurrency limit multiplies by replica count
> It is enforced per replica, so the effective ceiling on your backend is the configured value **×
> the number of replicas**. Scaling pivot out raises the load the backend can see unless this is
> lowered to match. `pivot backend show` states the figure and this caveat.

When no backend slot frees up in time, pivot answers `503` with `Retry-After`. That is the honest
answer: the request was not wrong, pivot is protecting the backend from it.

The rate limiter **fails open** if Valkey is unreachable. That is the uncomfortable direction and
the deliberate one — the alternative is a Valkey hiccup taking every customer offline, and the
backend still has its own concurrency limit and its own permissions. The log records every such
window.

## Caching

Only routes explicitly marked cacheable are cached, for the TTL that route declares. The key covers
the client, the method, the normalized path, the canonical query string and a hash of the body.

```sh
pivot cache purge            # after narrowing a rule, or fixing a shared route
pivot rules test /api/search/product   # reports the route's cache configuration
```

Three behaviours are properties rather than details:

- **The backend's directives are honoured.** `Cache-Control: no-store`, `private` and `no-cache` all
  prevent caching, because a proxy that ignored them would be caching exactly what the backend was
  careful about. So does a `Set-Cookie`, and so does a `Vary` on anything the key does not cover.
- **Replayed headers are an allowlist.** A cached response goes to a different request than the one
  that produced it, so `Set-Cookie` above all must not come along — and a header the backend invents
  later is dropped rather than replayed.
- **Only `200` is cached.** A `404` or `403` is cheap to produce and caching one would make a
  transient backend state stick; a `5xx` must never be replayed as though it were an answer.

Uncacheable routes are **streamed** straight through with no size limit, so a large export works. A
cacheable route whose response exceeds 32 MiB is reported rather than served uncached — the operator
asked for it to be cached and it never will be.

### Per-route encryption

```yaml
routes:
  - { glob: "/api/search/order", cache: { ttl: 1m, encrypt: true } }
```

> [!CAUTION] pivot cannot work out which routes need this
> A route's path does not reveal whether its responses carry personal data: associations can pull
> personal data into an otherwise harmless search. The flag is an operator judgement per route, and
> the default (off) is the unsafe direction for anything touching customer data.

An entry stored in the clear for a route that now requires encryption is **discarded as a cache
miss** rather than served, because it holds exactly the data the operator decided needed protecting.

### `shared` routes

A route may be marked `shared`, which drops the client from the cache key so one entry serves every
customer. Only correct when the response cannot differ between clients — and two clients with
different backend permissions can get different responses from one path, which pivot cannot detect.
This is the one setting here that can leak data between customers if it is wrong.

## Backend credentials

Each customer maps to its own backend credentials, so its requests reach the backend as that
customer's own integration with that integration's permissions. That is the second of the two
layers.

```sh
pivot client backend <client-id> --backend-mode oauth2 \
  --backend-client-id "$ID" --backend-client-secret "$SECRET"

pivot backend test --client <client-id>
pivot backend show
```

| Mode         | What pivot sends on the forward leg                        |
| ------------ | ---------------------------------------------------------- |
| `oauth2`     | A client-credentials token, fetched and refreshed by pivot |
| `http-basic` | HTTP Basic credentials                                     |
| `api-key`    | A static key in a configurable header                      |

In `oauth2` mode the token is refreshed a minute before expiry, not at it — a token that expires
mid-flight is a 401 the customer reads as pivot's failure. Tokens are **shared across replicas**
through Valkey, which matters beyond efficiency: a backend that invalidates the previous token when
it issues a new one would otherwise have your replicas revoking each other's.

The customer's own `Authorization` header is dropped on the forward leg, along with `Cookie` and the
forwarding headers. A client's `X-Forwarded-For` is a claim, and appending to it would let a
customer prepend whatever it liked to the chain the backend reads.

> [!IMPORTANT] pivot bounds the damage; it does not fix the backend
> A customer granted too many backend permissions on an allowed route gets that data. Data reachable
> through an allowed entity's associations — customer data on an order search, for instance — is
> controlled by the backend ACL alone, and no path rule can see it. And the backend must not be
> reachable by customers directly, or pivot is simply bypassed.

## TLS

```sh
# Native TLS
pivot server start --tls-cert /etc/pivot/tls/cert.pem --tls-key /etc/pivot/tls/key.pem

# Behind an ingress or reverse proxy, which is the expected deployment
pivot server start --listen 127.0.0.1:8443 --trusted-proxies 10.0.0.0/8
```

pivot refuses a request it can see arrived over plain HTTP, because customers send credentials on
every single request and one on a plaintext hop is a disclosed credential the client will keep
sending.

With no `--trusted-proxies` declared, pivot cannot tell a proxied HTTPS request from a direct
plaintext one and tolerates it rather than guessing — refusing would break the expected deployment
over a header the operator may not control. The startup log warns about that configuration, because
in it the client address pivot records and rate-limits on is the proxy's.

> [!CAUTION] The ingress must pass the path through unmodified
> Rule matching depends on pivot and the backend's router seeing the same request. A proxy that
> rewrites or re-encodes the path before pivot sees it reintroduces exactly the second interpretation
> the normalization exists to eliminate.

## Running several replicas

All shared state lives in Valkey, so replicas hold nothing that cannot be lost and need no consensus.

A change made through **any** replica's admin socket applies to all of them: it is written to Valkey,
a version counter is incremented, and the change is announced on a Valkey channel. Replicas also poll
that counter every fifteen seconds, because pub/sub has no delivery guarantee — the counter is what
makes convergence certain and the announcement is what makes it fast.

```sh
kubectl exec deploy/pivot -- pivot rules apply --deny-all
kubectl exec deploy/pivot -- pivot version      # names the replica that answered
```

`version` and `config view` report the answering replica and its rule version, because two replicas
disagreeing is something you need to be able to see rather than guess at.

Notifications are claimed before delivery with a lease, so one replica sends each one rather than
all of them. `pivot outbox status` reports who holds what: "nothing is draining" has a very
different cause when every entry is claimed by a replica that no longer exists.

## Administration

Everything other than `server start` is a short-lived client of a replica's Unix domain socket. The
socket is created `0600` and owned by the service user, and those permissions are the entire
authorization model — there is no network administration API.

```sh
pivot client list
pivot token list --client <client-id>
pivot audit list --kind admin
pivot outbox status --dead
pivot config view
```

Every administrative action is recorded with the operator's identity, taken from the kernel through
`SO_PEERCRED` rather than from anything the request claimed:

```text
level=INFO msg=audit kind=admin action=rules.apply actor="deploy(uid=997 pid=4213)" subject=global
```

`--json` on any command produces machine-readable output, and `--socket` reaches a specific replica.

## Runtime settings

Stored in Valkey and applied without a restart, on every replica.

| Setting                        | Default            | What it does                                             |
| ------------------------------ | ------------------ | -------------------------------------------------------- |
| `frontend.auth_mode`           | `oauth2`           | how customers authenticate                               |
| `frontend.auth_path`           | `/api/oauth/token` | where pivot answers its own token endpoint               |
| `backend.url`                  | unset              | the origin requests are forwarded to                     |
| `backend.concurrency`          | `16`               | simultaneous backend calls **per replica**               |
| `token.lifetime`               | `10m`              | how long an issued access token is valid                 |
| `ratelimit.default_burst`      | `0`                | burst for a client with no limit of its own; 0 unlimited |
| `ratelimit.default_per_second` | `0`                | sustained rate for the same                              |
| `cache.coalesce`               | `true`             | identical concurrent requests share one backend call     |
| `audit.retention`              | `2160h` (90 days)  | how long pivot keeps its own audit records               |
| `accesslog.client_address`     | `anonymised`       | `full`, `anonymised` or `off` (GDPR-relevant)            |
| `events.dedup_window`          | `0`                | collapse identical events; `0` delivers every one        |
| `log.level`                    | bootstrap          | `debug`, `info`, `warn` or `error`, without a restart    |

## Bootstrap configuration

Needed before Valkey can be reached, so these are flags and environment variables. A flag beats an
environment variable.

| Flag                | Environment                  | Default                 |
| ------------------- | ---------------------------- | ----------------------- |
| `--listen`          | `PIVOT_LISTEN`               | `:8443`                 |
| `--socket`          | `PIVOT_SOCKET`               | `/run/pivot/admin.sock` |
| `--valkey`          | `PIVOT_VALKEY_ADDRESS`       | `127.0.0.1:6379`        |
| `--valkey-username` | `PIVOT_VALKEY_USERNAME`      | unset                   |
| `--valkey-db`       | `PIVOT_VALKEY_DB`            | `0`                     |
| `--valkey-tls`      | `PIVOT_VALKEY_TLS`           | `false`                 |
| `--replica`         | `PIVOT_REPLICA`              | the hostname            |
| `--tls-cert`        | `PIVOT_TLS_CERT`             | unset                   |
| `--tls-key`         | `PIVOT_TLS_KEY`              | unset                   |
| `--trusted-proxies` | `PIVOT_TRUSTED_PROXIES`      | unset                   |
| `--backend-timeout` | `PIVOT_BACKEND_TIMEOUT`      | `30s`                   |
| `--log-level`       | `PIVOT_LOG_LEVEL`            | `info`                  |
| `--log-format`      | `PIVOT_LOG_FORMAT`           | `text`                  |
|                     | `PIVOT_SHUTDOWN_GRACE`       | `30s`                   |
|                     | `PIVOT_SECRET` / `_FILE`     | —                       |
|                     | `PIVOT_VALKEY_PASSWORD`      | —                       |
|                     | `PIVOT_VALKEY_PASSWORD_FILE` | —                       |

There is deliberately no flag for either password: a password on a command line is a password in the
process list.

## What is stored, and how

Valkey has **no encryption at rest**, so pivot encrypts what needs it before writing, with keys
derived from `PIVOT_SECRET` under purpose-specific HKDF labels.

| Data                           | Stored as                                   |
| ------------------------------ | ------------------------------------------- |
| Client ids and secrets         | SHA-256 hash                                |
| Issued access tokens           | SHA-256 hash, keyed by the hash, with a TTL |
| Backend credentials and tokens | AES-256-GCM encrypted                       |
| Notifier credentials           | AES-256-GCM encrypted                       |
| Rate-limit buckets             | Plain, with a TTL                           |
| Cached responses               | Plain, or encrypted per route               |
| Audit records                  | Plain, with the retention as a TTL          |

The token store holds no usable token: the key _is_ the hash. A Valkey snapshot therefore carries no
credential a reader could present.

Secure your Valkey as well. `--valkey-tls` and a Valkey ACL user are the minimum for anything but a
loopback deployment.

## Notifications

```sh
pivot notifier add ops-mail --kind smtp \
  --set host=smtp.example.org --set from=pivot@example.org \
  --set to=ops@example.org --set password="$SMTP_PASSWORD"
pivot notifier test ops-mail
```

| Event                 | Fires on                                                |
| --------------------- | ------------------------------------------------------- |
| `client.auth_failed`  | repeated failed authentication for one client or source |
| `rule.denied`         | requests denied by a rule, aggregated                   |
| `client.rate_limited` | a client exceeding its limit, aggregated                |
| `backend.failed`      | backend errors or timeouts above a threshold            |
| `backend.auth_failed` | the backend rejecting pivot's own credentials           |

Every one is an aggregate or an incident. There is deliberately no per-request event: the proxy
carries whatever volume customers send, so one event per request would be a denial-of-service
amplifier pointed at your mailbox.

Aggregation is **per replica**, which is a limitation worth knowing: a denial rate spread evenly
across ten replicas reaches a tenth of the threshold on each, so it may not be notified at all.
Counting in Valkey would fix that and would put a write on the hot path of every denied request. The
per-request log line is emitted regardless, so what is aggregated is only the notification.

## Container image

Published to `ghcr.io/adnoctem/pivot` on every release, as a multi-architecture index covering
`linux/amd64` and `linux/arm64`.

```sh
docker pull ghcr.io/adnoctem/pivot:1.4.0
```

Every release is tagged with its exact version, and `latest` is moved to the newest one. Deploy the
exact version. `latest` is for a first look: a proxy whose rule engine changes under you without a
deployment is not what belongs in front of a production API.

What is in the image:

| Property   | Value                                                                                       |
| ---------- | ------------------------------------------------------------------------------------------- |
| base       | `gcr.io/distroless/static-debian12:nonroot`, pinned by digest in `MODULE.bazel`             |
| contents   | `/pivot`, mode `0555`, and the base's CA bundle. No shell, no package manager, nothing else |
| user       | `65532:65532`, declared in the image, so nothing has to be overridden to avoid root         |
| entrypoint | `/pivot` — the subcommand is the argument                                                   |
| ports      | `8443/tcp`, declared for whoever reads `docker inspect`; it opens nothing by itself         |
| writable   | `/run/pivot` only, `0700` and owned by `65532`                                              |
| size       | about 20 MB                                                                                 |

The CA bundle is why the base is not empty. pivot's forward leg is HTTPS — to your backend and to
its token endpoint — and a container with no trust roots cannot verify either. It would fail every
request with a certificate error that reads like a misconfiguration and is not one.

### Running it

```sh
docker run -d --name pivot \
  -p 8443:8443 \
  -e PIVOT_SECRET_FILE=/etc/pivot/secret \
  -e PIVOT_VALKEY_ADDRESS=valkey:6379 \
  -e PIVOT_REPLICA=pivot-1 \
  -v /etc/pivot/secret:/etc/pivot/secret:ro \
  ghcr.io/adnoctem/pivot:1.4.0 server start
```

pivot keeps nothing on disk, so there is no volume to mount and a replaced container loses nothing —
provided the replacement is given the same `PIVOT_SECRET`. With a different one it starts cleanly,
answers `/healthz`, and then fails every forward leg, because the backend credentials in Valkey were
sealed with keys derived from the old secret. That failure mode is the reason the secret belongs in
a secret store and not in a deployment manifest.

### Administering a running container

The admin socket is a Unix socket inside the container, so admin commands run inside the container:

```sh
docker exec pivot /pivot config view
docker exec pivot /pivot backend set https://shop.internal.example
docker exec pivot /pivot client list

# A rule set is read by the CLI, not the server, so the file has to be inside
# the container. `--deny-all` needs none, which is the point of having it.
docker cp ./shopware-readonly.yaml pivot:/tmp/
docker exec pivot /pivot rules apply /tmp/shopware-readonly.yaml
docker exec pivot /pivot rules apply --deny-all
```

There is no shell in the image, so `docker exec -it pivot sh` fails. That is the point of a
distroless base: what is in the image is the service, and nothing that would be useful to someone
who got into it. Call the binary directly.

Access to the socket is by file permission — it sits in a `0700` directory owned by `65532` — so the
caller has to be that user or root. `docker exec` runs as the image's user by default, which is the
right one. The audit record names whichever uid connected, so an exec as root is recorded as
`uid=0`.

Any replica will do: clients, rules and settings live in Valkey, and the replica you reach announces
the change to the others. `pivot backend test --client <id>` is worth running once from inside a
container, because it is the one command that proves the forward leg works end to end from where it
will actually run — credentials, DNS, and certificate verification against the CA bundle above.

### Building it yourself

```sh
bazel run   --config=release //cmd/pivot:load      # loads pivot:dev locally
bazel build --config=release //cmd/pivot:tarball   # docker-format tarball, for a registry-less cluster
bazel build --config=release //cmd/pivot:image     # the multi-arch index, as an OCI layout
```

`--config=release` is what the published images are built with: it is the difference between the
binary that ships and a debug build nearly twice the size. Leave it off and the image still works,
which is what you want when the reason you are building one is to debug something in it.

`:load` builds the amd64 image only, because loading an index into a Docker engine is not something
it does. The image is defined in [`scripts/bazel/image.bzl`](../../scripts/bazel/image.bzl).

## Running under Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pivot
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pivot
  template:
    metadata:
      labels:
        app: pivot
    spec:
      securityContext:
        # The image already runs as 65532. This is the pod asserting it, which
        # is what the "restricted" Pod Security Standard checks - the standard
        # does not read the image to find out.
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: pivot
          image: ghcr.io/adnoctem/pivot:1.4.0
          args: ["server", "start"]
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          env:
            # Every replica must share this. A replica with a different secret
            # starts cleanly and then fails every forward leg.
            - name: PIVOT_SECRET_FILE
              value: /etc/pivot/secret
            - name: PIVOT_VALKEY_ADDRESS
              value: valkey.internal:6379
            - name: PIVOT_VALKEY_PASSWORD_FILE
              value: /etc/pivot/valkey-password
            # The pod name, so log lines and outbox claims name something an
            # operator can find.
            - name: PIVOT_REPLICA
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: PIVOT_TRUSTED_PROXIES
              value: 10.0.0.0/8
            - name: PIVOT_LOG_FORMAT
              value: json
          volumeMounts:
            - name: secret
              mountPath: /etc/pivot
              readOnly: true
          livenessProbe:
            httpGet: { path: /healthz, port: 8443 }
          readinessProbe:
            # Not the same endpoint. /healthz reports the process; /readyz
            # reports whether this replica can actually serve - Valkey
            # reachable and a rule set loaded.
            httpGet: { path: /readyz, port: 8443 }
      volumes:
        - name: secret
          secret:
            secretName: pivot
```

Remember to lower `backend.concurrency` as you scale out, or the effective ceiling on your backend
rises with the replica count.

No `readOnlyRootFilesystem` above, and the reason is the admin socket. pivot writes to exactly one
path, `/run/pivot`, which the image already contains as `0700` owned by `65532` — the mode the
socket's access control depends on, since reaching the socket is reaching the admin API. A read-only
root filesystem means mounting something over that path instead, and an `emptyDir` arrives
root-owned, so it also needs `fsGroup`:

```yaml
spec:
  securityContext:
    fsGroup: 65532
  containers:
    - name: pivot
      securityContext:
        readOnlyRootFilesystem: true
      volumeMounts:
        - name: run
          mountPath: /run/pivot
  volumes:
    - name: run
      emptyDir:
        medium: Memory
```

That works, and is what to use where policy requires it, but be clear about what it changes: the
directory is then group-writable rather than `0700`, so the socket is reachable by anything running
as group `65532` in that pod. With one container in the pod there is nothing else to reach it; with
a sidecar, there is.

`kubectl exec` is how a pod-hosted instance is administered, and it needs no shell:

```sh
kubectl exec deploy/pivot -- /pivot config view
kubectl exec deploy/pivot -- /pivot rules test /api/product --client acme
```

## Operational notes

- **A fresh pivot denies everything and reports itself not ready.** That is the right default for a
  service whose job is to refuse — a deployment that forgot to apply a rule set does not quietly
  send customers 403s.
- **A 403 says nothing about why.** Which rule denied a request, and whether any rule matched at
  all, is information about your policy; a customer enumerating paths against the error text would
  be mapping the rule set. Use `pivot rules test` to find out.
- **A 401 says nothing about which half was wrong.** Unknown client, wrong secret and expired token
  are one answer, because distinguishing them turns one search space into two much smaller ones.
- **Disabling a client revokes its tokens.** A suspended customer that kept working until its tokens
  expired is not what "disabled" means, so re-enabling it needs a fresh exchange.
- **A rule set that does not compile is never stored.** Storing one would leave every replica failing
  its next reload and serving whatever it had — a change that appears to have worked and did not.
- **One client's broken rules do not break the others.** That client falls back to the global set,
  which is the restrictive direction, and the log says so.
- **`secret rotate` is not implemented.** To rotate by hand: stop every replica, start them with the
  new secret, and re-enter the backend credentials with `pivot client backend`. The client ids,
  secrets and rules survive; only the encrypted values need replacing.

Linux is the only platform pivot is supported as a server on. macOS binaries ship as well,
for the subcommands that need no server - `pivot rules validate`, `pivot secret generate` and `pivot version` - which is
what runs on a laptop or in a CI job. No Windows binaries are shipped.
