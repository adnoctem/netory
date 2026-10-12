# signpost

Public script router. It takes a bundle of scripts plus one manifest and serves each script at a
configured URL path, for the one-line install pattern — `curl -fsSL https://example.org/install.sh |
sh`.

The constraint that drives every decision here: **the served bytes are executed verbatim by the
client, unreviewed.** Immutable releases, atomic alias swaps, extraction hardening, truncation
protection and HTTPS-only serving all follow from that one fact.

For scope, architecture and the reasoning, read [`docs/design/signpost.md`](../../docs/design/signpost.md).
This file is how to run it.

## Installation

signpost is one static executable with no runtime dependencies. Releases publish it for `linux` and
`darwin`, each for `amd64` and `arm64`:

```sh
curl -fsSL https://github.com/adnoctem/netory/releases/latest/download/signpost_linux_amd64.tar.gz \
  | tar -xzf - signpost
sudo install -m 0755 signpost /usr/local/bin/signpost
```

To check it against the release's checksums before installing it:

```sh
base=https://github.com/adnoctem/netory/releases/latest/download
curl -fsSLO "$base/signpost_linux_amd64.tar.gz"
curl -fsSL "$base/CHECKSUMS_SHA256.txt" | sha256sum -c --ignore-missing   # shasum -a 256 on macOS
tar -xzf signpost_linux_amd64.tar.gz signpost
```

Replace `latest` with a tag such as `v0.1.0` to pin a release. Run the server on Linux; the macOS build is for `bundle validate`, which checks a bundle exactly as a publish would, without a server. The container image is
`ghcr.io/adnoctem/signpost` — see [Container image](#container-image) — and building from source is
`bazel build --config=release //cmd/signpost`; see [`docs/CONTRIBUTING.md`](../../docs/CONTRIBUTING.md).

## Quick start

```sh
# 1. Generate a secret. A file is better than an environment variable:
#    /proc/<pid>/environ is readable by the process owner, and environment
#    variables are inherited by child processes.
install -d -m 0700 /etc/signpost
signpost secret generate > /etc/signpost/secret
chmod 0600 /etc/signpost/secret

# 2. Start the server. This is the only process that opens the database.
export SIGNPOST_SECRET_FILE=/etc/signpost/secret
signpost server start \
  --listen :8443 \
  --tls-cert /etc/signpost/tls/cert.pem \
  --tls-key /etc/signpost/tls/key.pem \
  --database /var/lib/signpost/db \
  --content /var/lib/signpost/content

# 3. In another shell, as the same user, publish a bundle.
signpost bundle validate install-1.4.0.tar.gz
signpost bundle publish install-1.4.0.tar.gz
```

That last command creates release `1.4.0` and moves the `latest` alias to it. The routes are live
the moment the alias moves, and not before.

## Building a bundle

A bundle is one `.zip` or `.tar.gz` containing your scripts and exactly one manifest at the archive
root, named `signpost.yaml`, `signpost.yml` or `signpost.json`.

```text
install-1.4.0.tar.gz
├── signpost.yaml
└── scripts/
    ├── install.sh
    └── install.ps1
```

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

`content_type` is optional; it is inferred from the file extension when absent, falling back to
`text/plain` so a cautious user can read a script in a browser before piping it.

A JSON Schema for the manifest is published at
[`docs/schema/signpost-manifest-v1.json`](../../docs/schema/signpost-manifest-v1.json). Point your editor at it
for completion and inline errors. It is generated from the Go types that validate the manifest, so
the two cannot drift — but it only describes a well-formed manifest. Reserved paths, route
uniqueness, that every referenced file is in the archive, and the truncation check are things JSON
Schema cannot express, and `signpost bundle validate` is the thing that checks them.

### Truncation protection

A connection drop mid-download can execute half a script. signpost refuses to publish a shell or
PowerShell script whose logic is not wrapped in a function that is only invoked on the last line:

```sh
#!/bin/sh
set -eu

VERSION=1.4.0

main() {
    # everything that acts on the system goes here
}

main "$@"
```

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Install-Thing {
    # everything that acts on the system goes here
}

Install-Thing
```

Top-level lines before the wrapper may set shell options and assign literals. A top-level command —
including an assignment whose value is a command substitution, such as `VERSION=$(curl …)` — is a
line a truncated download could execute, so it is refused.

The check is structural, not semantic. It verifies that a script _can_ only act once fully received;
it cannot verify that the script is safe, correct, or that its logic is genuinely confined to the
wrapper.

If the check is wrong about a legitimate script, opt that one route out:

```yaml
routes:
  - path: /install.sh
    file: scripts/install.sh
    skip_truncation_check: true
```

Opting out is deliberate and recorded: `bundle list` reports it, the publish event carries it, and
the publish output warns about it. An instance can refuse it outright with
`signpost config set publish.allow_truncation_opt_out false`.

## What gets served

For release `1.4.0` with the manifest above, and `latest` pointing at it:

| Path                        | Serves                  | Cache                         |
| --------------------------- | ----------------------- | ----------------------------- |
| `/install.sh`               | the `latest` release    | `max-age=60, must-revalidate` |
| `/install.sh.sha256`        | its SHA-256             | as above                      |
| `/v1.4.0/install.sh`        | release `1.4.0`, pinned | `max-age=31536000, immutable` |
| `/v1.4.0/install.sh.sha256` | its SHA-256             | as above                      |
| `/healthz`                  | `ok`                    | `no-store`                    |

The cache split follows from the mutability split. An alias route changes meaning at the next
publish, so a long cache would keep serving a release a rollback was meant to retract. A versioned
route cannot change by construction, so it is cacheable for as long as HTTP allows. Both lifetimes
are configurable; see [runtime settings](#runtime-settings).

Every response carries `ETag` derived from the content hash, `X-Content-Type-Options: nosniff`,
`X-Signpost-Release` naming the release served, and an explicit `Content-Length` — a client piping
into a shell can only detect a truncated download if it was told how much to expect.

The checksum route is sha256sum's own format, so it pipes straight into verification:

```sh
curl -fsSLO https://example.org/install.sh
curl -fsSLO https://example.org/install.sh.sha256
sha256sum -c install.sh.sha256
```

An unknown path returns 404 with no body. A list of install scripts is a list of what an
organisation deploys, so there is no index and no listing.

## HTTPS only

signpost refuses to serve a script over a connection it cannot confirm was encrypted, and answers
`421 Misdirected Request` instead. There are two supported deployments.

**Native TLS.** Pass `--tls-cert` and `--tls-key`. The connection itself is the evidence; nothing
else is needed. ACME is not implemented — use your existing certificate tooling.

**Behind a reverse proxy.** Leave the TLS flags out and declare the proxy:

```sh
signpost server start --listen 127.0.0.1:8443 --trusted-proxies 10.0.0.0/8,192.168.1.5
```

In this mode signpost receives plain HTTP by design and cannot tell a proxied HTTPS request from a
direct plaintext one by the connection alone, so it trusts `X-Forwarded-Proto` **only** from a peer
in that list. Your proxy must send it:

```nginx
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
```

With no `--trusted-proxies` and no certificate, signpost cannot confirm the transport for any
request and will refuse to serve every script. It warns about this at startup rather than leaving
you to discover a wall of 421s. A redirect to `https://` would be friendlier and wrong: a client
that followed it has already sent the request in the clear, and `curl | sh` without `-L` would pipe
the redirect body into a shell.

`/healthz` is served over plain HTTP, because a liveness probe is not a script and a health check
that failed for not using TLS would make a healthy service look dead.

## Releases, aliases and rollback

A release is immutable. Publishing the same release identifier twice is refused rather than
replacing bytes that clients may already have checksummed — bump the version in the manifest.

An alias is a movable name for one release. Publishing moves the serving alias; `bundle rollback`
moves it back.

```sh
# Publish and move specific aliases rather than the default one.
signpost bundle publish install-1.5.0.tar.gz --alias latest --alias stable

# Stage a release without serving it on the unversioned paths. It is reachable
# at /v1.5.0/... immediately, which is how a pinned install can be tested
# before it becomes the default.
signpost bundle publish install-1.5.0.tar.gz --no-alias
signpost alias set latest 1.5.0

# Undo the publish that just broke.
signpost bundle rollback
signpost bundle rollback --alias stable
```

signpost keeps one step of history per alias, which is enough for the job rollback exists to do. A
second rollback returns to the release the first one left, so rollback is its own undo.

```sh
signpost bundle list        # * marks the release being served
signpost alias list         # * marks the alias the unversioned routes come from
signpost bundle remove 1.0.0
```

`bundle remove` is refused while any alias points at the release, because the routes that alias
serves would otherwise resolve to nothing. Note that releases are meant to be retained so any script
ever served can be reproduced for an audit — removing one is a deliberate departure from that, not
routine housekeeping.

Removing the serving alias is refused too. Point `serve.alias` elsewhere first, so retiring an
install URL is always a deliberate two-step act.

## Signing

Signature verification is optional and minisign-compatible. Both of minisign's algorithms are
supported: `Ed` over the file, and `ED` over its BLAKE2b-512 hash, which is what the current CLI
emits.

```sh
# Sign the bundle, once, wherever you build it.
minisign -Sm install-1.4.0.tar.gz

# Trust the key, once.
signpost config set publish.signing_key 'RWQf6LRCGA9i53ml…'

# Publish with the detached signature.
signpost bundle publish install-1.4.0.tar.gz --signature install-1.4.0.tar.gz.minisig
```

Once a key is configured, make it mandatory:

```sh
signpost config set publish.require_signature true
```

With that set, the signature is verified **before the archive is unpacked**. The extractor is the
one component that processes attacker-shaped input, so when a signature is required nothing hostile
reaches it until the bytes are known to come from the trusted key.

A signature that is supplied but cannot be checked — no configured key, wrong key, altered bytes —
is an error, never a quiet downgrade to "unsigned". `--public-key` overrides the configured key for
one publish, which is how a key rotation happens without a window in which nothing verifies.

The key ID and minisign's trusted comment are recorded on the release and shown by `bundle list`,
because the audit trail is expected to carry signature status.

PowerShell scripts can be Authenticode-signed before bundling so they run without lowering
`ExecutionPolicy`. signpost serves them unchanged.

## Administration

Everything other than `server start` is a short-lived client of a Unix domain socket. The socket is
created `0600` and owned by the service user, and those permissions are the entire authorization
model — there is no network publishing API, so there is nothing remote to authenticate.

Publishing from CI goes through SSH or `docker exec` and then the local CLI:

```sh
scp install-1.4.0.tar.gz install-1.4.0.tar.gz.minisig deploy@host:/tmp/
ssh deploy@host 'signpost bundle publish /tmp/install-1.4.0.tar.gz \
  --signature /tmp/install-1.4.0.tar.gz.minisig'
```

The bundle is a file argument rather than something read from stdin: the CLI stats and size-checks
it before uploading, and an error naming the path is more use than one naming a pipe.

Every publish, rollback, alias change and removal is written to the log with the operator's
identity, taken from the kernel through `SO_PEERCRED` rather than from anything the request claimed:

```text
level=INFO msg="release published" release=1.4.0 routes=2 signature=unsigned by="deploy(uid=997 pid=4213)"
```

Mutations log at info and reads at debug, so a monitoring script polling `bundle list` cannot bury
the one `bundle remove` you are looking for.

`--json` on any command produces machine-readable output, and `--socket` reaches a server configured
with a non-default path.

## Runtime settings

Stored in the database and applied without a restart.

```sh
signpost config view          # the whole active configuration at a glance
signpost config list          # every setting, with what it accepts
signpost config get serve.alias
signpost config set cache.alias_max_age 30s
```

| Setting                            | Default      | What it does                                          |
| ---------------------------------- | ------------ | ----------------------------------------------------- |
| `serve.alias`                      | `latest`     | which alias the unversioned routes come from          |
| `serve.versioned`                  | `true`       | serve `/v<release>/<path>` for pinned installs        |
| `cache.alias_max_age`              | `1m`         | how long an alias route may be cached                 |
| `cache.versioned_max_age`          | `8760h`      | how long a versioned route may be cached              |
| `accesslog.client_address`         | `anonymised` | `full`, `anonymised` or `off` (GDPR-relevant)         |
| `publish.require_signature`        | `false`      | refuse a publish without a verified signature         |
| `publish.signing_key`              | none         | the trusted minisign public key                       |
| `publish.allow_truncation_opt_out` | `true`       | allow a manifest to skip the truncation check         |
| `events.dedup_window`              | `0`          | collapse identical events; `0` delivers every one     |
| `log.level`                        | bootstrap    | `debug`, `info`, `warn` or `error`, without a restart |

`events.dedup_window` is zero on purpose, unlike protean's. Every signpost event is a human
administrative act arriving over a local socket, so there is nothing to flap — and the one sequence
collapsing would eat is publish, notice, roll back, which is the sequence an operator most needs to
hear in full.

## Bootstrap configuration

These are needed before the database can be opened, so they are flags and environment variables
rather than settings. A flag beats an environment variable.

| Flag                | Environment                | Default                     |
| ------------------- | -------------------------- | --------------------------- |
| `--listen`          | `SIGNPOST_LISTEN`          | `:8443`                     |
| `--socket`          | `SIGNPOST_SOCKET`          | `/run/signpost/admin.sock`  |
| `--database`        | `SIGNPOST_DATABASE`        | `/var/lib/signpost/db`      |
| `--content`         | `SIGNPOST_CONTENT`         | `/var/lib/signpost/content` |
| `--tls-cert`        | `SIGNPOST_TLS_CERT`        | unset                       |
| `--tls-key`         | `SIGNPOST_TLS_KEY`         | unset                       |
| `--trusted-proxies` | `SIGNPOST_TRUSTED_PROXIES` | unset                       |
| `--log-level`       | `SIGNPOST_LOG_LEVEL`       | `info`                      |
| `--log-format`      | `SIGNPOST_LOG_FORMAT`      | `text`                      |
|                     | `SIGNPOST_SHUTDOWN_GRACE`  | `15s`                       |
|                     | `SIGNPOST_SECRET`          | —                           |
|                     | `SIGNPOST_SECRET_FILE`     | —                           |

The admin socket path is limited to 106 bytes by the kernel, and signpost says so rather than
failing with `bind: invalid argument`.

## Where things live

Release metadata — routes, digests, signature status, who published what and when — lives in the
encrypted Badger database. The script contents live in the content directory, one subdirectory per
release, each file named after its own SHA-256 and created `0600` under a `0700` tree.

Content is read back by digest and verified on every read that is not already cached, so a file
altered on disk is detected and the request fails rather than serving bytes nobody published. That
is the guarantee this service sells.

Both directories are needed for a working signpost, and they must be different directories: Badger
owns its own.

## Notifications

```sh
signpost notifier add ops-mail --kind smtp \
  --set host=smtp.example.org --set from=signpost@example.org \
  --set to=ops@example.org --set password="$SMTP_PASSWORD"
signpost notifier test ops-mail
signpost notifier list          # credentials are always redacted
```

| Event              | Fires on                             |
| ------------------ | ------------------------------------ |
| `bundle.published` | a new release                        |
| `bundle.rejected`  | validation failed on publish         |
| `alias.changed`    | an alias moved, including a rollback |
| `bundle.removed`   | a release was deleted                |

There is deliberately no event for a served request: signpost serves anonymously and at whatever
rate the internet brings, so an event per request would be a denial-of-service amplifier pointed at
your mailbox.

Events are persisted before any delivery is attempted, so a relay outage delays notifications rather
than dropping them. `signpost outbox status --pending` shows what is waiting and `--dead` what was
abandoned after its retries.

Webhook notifiers are signed with an HMAC key derived from `SIGNPOST_SECRET`; the signature covers
the timestamp and the body.

## Running under systemd

```ini
# /etc/systemd/system/signpost.service
[Unit]
Description=signpost public script router
After=network-online.target

[Service]
Type=simple
User=signpost
Group=signpost
# systemd places the secret at %d/secret and signpost reads it from there.
LoadCredential=secret:/etc/signpost/secret
Environment=SIGNPOST_SECRET_FILE=%d/secret
ExecStart=/usr/local/bin/signpost server start
Restart=on-failure

RuntimeDirectory=signpost
RuntimeDirectoryMode=0750
StateDirectory=signpost
StateDirectoryMode=0750

# The database holds notifier credentials; the content tree holds the bytes
# clients execute. signpost needs no more than its own files and a listening
# socket.
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
# Binding :8443 needs no capability; a port below 1024 would need
# AmbientCapabilities=CAP_NET_BIND_SERVICE.

[Install]
WantedBy=multi-user.target
```

Only one process may open the database. Badger holds an exclusive lock on its directory, so a second
`server start` fails rather than corrupting anything — the constraint is enforced, not just
documented.

## Container image

Published to `ghcr.io/adnoctem/signpost` on every release, as a multi-architecture index covering
`linux/amd64` and `linux/arm64`.

```sh
docker pull ghcr.io/adnoctem/signpost:1.4.0
```

Every release is tagged with its exact version, and `latest` is moved to the newest one. Pin the
version in anything you deploy; `latest` is for a first look.

What is in the image:

| Property   | Value                                                                                            |
| ---------- | ------------------------------------------------------------------------------------------------ |
| base       | `gcr.io/distroless/static-debian12:nonroot`, pinned by digest in `MODULE.bazel`                  |
| contents   | `/signpost`, mode `0555`, and the base's CA bundle. No shell, no package manager, nothing else   |
| user       | `65532:65532`, declared in the image, so nothing has to be overridden to avoid root              |
| entrypoint | `/signpost` — the subcommand is the argument                                                     |
| ports      | `8443/tcp`, declared for whoever reads `docker inspect`; it opens nothing by itself              |
| writable   | `/var/lib/signpost/db`, `/var/lib/signpost/content` and `/run/signpost`, `0700` owned by `65532` |
| size       | about 28 MB                                                                                      |

The CA bundle is why the base is not empty: signpost's webhook notifier posts to an HTTPS endpoint,
and a container with no trust roots cannot verify one.

### Running it

```sh
docker volume create signpost-data

docker run -d --name signpost \
  -p 8443:8443 \
  -e SIGNPOST_SECRET_FILE=/etc/signpost/secret \
  -v /etc/signpost/secret:/etc/signpost/secret:ro \
  -v signpost-data:/var/lib/signpost \
  ghcr.io/adnoctem/signpost:1.4.0 server start
```

One volume on `/var/lib/signpost` covers both the database and the content tree, which is why the
image creates them as `db` and `content` under one parent. They must stay separate directories —
Badger owns its own — but they do not need separate volumes, and **they must be backed up together**:
the database records which digest serves which route and the content tree holds the bytes, so either
one alone restores nothing.

A fresh named volume is initialised from the image's own directory, so `db/` and `content/` arrive
already owned by `65532` and this works without a `chown`. `/var/lib/signpost` itself stays
root-owned — signpost never creates anything directly in it, and a service that owned the parent
could rewrite the whole tree. A bind mount is the case that needs attention: a host directory
arrives with whatever it had, and `chown -R 65532:65532` on it is the fix.

`/run/signpost` holds the admin socket and is deliberately not a volume. It is recreated on every
start, and a socket that outlived its server would be a socket nothing is listening on.

> [!WARNING] The volume is worthless without the secret
> The database is encrypted with keys derived from `SIGNPOST_SECRET`, so a backed-up volume and a
> lost secret is a backup that opens nothing. Back the secret up separately.

### Publishing into a running container

The admin socket is a Unix socket inside the container, so admin commands run inside the container —
and so does reading the bundle. `signpost bundle publish` reads the archive itself and uploads it
across the socket, so the file has to be reachable from inside:

```sh
# Copy the bundle in, then publish it.
docker cp install-1.5.0.tar.gz signpost:/tmp/
docker exec signpost /signpost bundle validate /tmp/install-1.5.0.tar.gz
docker exec signpost /signpost bundle publish /tmp/install-1.5.0.tar.gz

docker exec signpost /signpost bundle list
docker exec signpost /signpost bundle rollback
```

Mounting the directory your CI writes bundles into works equally well and avoids the copy. Either
way the upload is capped at 64 MiB, the same limit the socket enforces everywhere else.

There is no shell in the image, so `docker exec -it signpost sh` fails. That is the point of a
distroless base: the image contains the service, and nothing that would help someone who got into
it — which matters more here than in most services, because what is on this disk is executed
verbatim by whoever runs your install line. Call the binary directly.

Access to the socket is by file permission — it sits in a `0700` directory owned by `65532` — so the
caller has to be that user or root. `docker exec` runs as the image's user by default, which is the
right one. The audit record names whichever uid connected, so an exec as root is recorded as
`uid=0`.

### Running under Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: signpost
spec:
  replicas: 1
  strategy:
    # Not RollingUpdate. Badger holds an exclusive lock on its directory, so
    # the new pod would fail to start while the old one still holds it - and a
    # rolling update that waits for a readiness it can never reach is a
    # deployment that hangs instead of one that fails.
    type: Recreate
  selector:
    matchLabels:
      app: signpost
  template:
    metadata:
      labels:
        app: signpost
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        # Makes the persistent volume group-writable by the service user. A
        # freshly provisioned volume is otherwise root-owned, and signpost
        # would fail to create its database in it.
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: signpost
          image: ghcr.io/adnoctem/signpost:1.4.0
          args: ["server", "start"]
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          env:
            - name: SIGNPOST_SECRET_FILE
              value: /etc/signpost/secret
            - name: SIGNPOST_TRUSTED_PROXIES
              value: 10.0.0.0/8
            - name: SIGNPOST_LOG_FORMAT
              value: json
          volumeMounts:
            - name: secret
              mountPath: /etc/signpost
              readOnly: true
            - name: data
              mountPath: /var/lib/signpost
          livenessProbe:
            httpGet: { path: /healthz, port: 8443 }
      volumes:
        - name: secret
          secret:
            secretName: signpost
        - name: data
          persistentVolumeClaim:
            claimName: signpost
```

One replica, and a `ReadWriteOnce` claim is correct rather than limiting: the database takes a single
writer, so a second replica would not share the load, it would fail to start. Put a CDN or an ingress
cache in front if the install line gets popular — the responses are immutable and carry long
cache headers precisely so that this is the way to scale reads.

Publishing from outside the cluster is the same two steps:

```sh
pod=$(kubectl get pod -l app=signpost -o jsonpath='{.items[0].metadata.name}')
kubectl cp install-1.5.0.tar.gz "$pod:/tmp/install-1.5.0.tar.gz"
kubectl exec "$pod" -- /signpost bundle publish /tmp/install-1.5.0.tar.gz
```

`kubectl cp` needs a pod name rather than a Deployment, which is the only reason for the first line;
`kubectl exec deploy/signpost -- /signpost bundle list` works directly.

`/run/signpost` is left to the image's own directory rather than mounted, so the manifest sets no
`readOnlyRootFilesystem`. With a policy that requires one, mount an in-memory `emptyDir` at
`/run/signpost`; with `fsGroup` already set above, the socket's directory then ends up
group-writable rather than `0700`, which matters only if something else runs in the pod.

### Building it yourself

```sh
bazel run   --config=release //cmd/signpost:load      # loads signpost:dev locally
bazel build --config=release //cmd/signpost:tarball   # docker-format tarball, for a registry-less cluster
bazel build --config=release //cmd/signpost:image     # the multi-arch index, as an OCI layout
```

`--config=release` is what the published images are built with: it is the difference between the
binary that ships and a debug build nearly twice the size. Leave it off and the image still works,
which is what you want when the reason you are building one is to debug something in it.

`:load` builds the amd64 image only, because loading an index into a Docker engine is not something
it does. The image is defined in [`scripts/bazel/image.bzl`](../../scripts/bazel/image.bzl).

## Operational notes

- **A bundle is rejected whole.** Nothing is partially published, so there is no state in which some
  routes are new and others are stale. A rejected publish emits `bundle.rejected` and leaves the
  database and content tree exactly as they were.
- **Archives are never unpacked onto disk.** A bundle is held in memory while it is validated —
  bounded at 64 MiB compressed, 256 MiB uncompressed, 8 MiB per file, 4096 entries — so a malicious
  archive never touches any filesystem. Absolute paths, `..` segments, symlinks and hardlinks are
  refused.
- **Publishing is atomic from the client's side.** Content is written, then the release record, then
  the alias, then the route table. An alias only ever names a release whose content is already
  there, and the serving snapshot is swapped whole, so no request sees a half-published state.
- **Two publishes of one release name cannot both win.** The release record is created with a
  compare-and-set, and an alias moves with a compare-and-swap against the release it was read at, so
  a losing publisher is told the alias moved rather than silently overwriting a release it never saw.
- **`secret rotate` is not implemented**, and deliberately not half-implemented. To rotate by hand,
  start with the new secret against an empty database and republish. The releases themselves are
  files on disk, so nothing is lost that way.
- **Client addresses in the access log are anonymised by default** — IPv4 to a `/24`, IPv6 to a
  `/48`. signpost cannot enforce a retention period for records that leave the process, so it
  controls what enters them instead; retention belongs to your log pipeline.

Linux is the only platform signpost is supported as a server on. macOS binaries ship as well,
for the subcommands that need no server - `signpost bundle validate`, `signpost secret generate` and `signpost version` - which is
what runs on a laptop or in a CI job. No Windows binaries are shipped.
