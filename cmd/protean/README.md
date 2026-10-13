# protean

Self-hosted dynDNS control plane. It accepts address updates from dynDNS clients and writes them to
an existing DNS provider.

protean owns no DNS data. Every record it touches lives at Cloudflare, Route 53 or Spaceship, and
the provider stays the source of truth — protean is a translation layer between authenticated update
requests and a provider API.

How protean works internally - providers, storage, backups and its known limitations - is described in the
[Architecture](../../docs/ARCHITECTURE.md#protean). This file is how to run it.

## Installation

protean is one static executable with no runtime dependencies. Releases publish it for `linux` and
`darwin`, each for `amd64` and `arm64`:

```sh
curl -fsSL https://github.com/adnoctem/netory/releases/latest/download/protean_linux_amd64.tar.gz \
  | tar -xzf - protean
sudo install -m 0755 protean /usr/local/bin/protean
```

To check it against the release's checksums before installing it:

```sh
base=https://github.com/adnoctem/netory/releases/latest/download
curl -fsSLO "$base/protean_linux_amd64.tar.gz"
curl -fsSL "$base/CHECKSUMS_SHA256.txt" | sha256sum -c --ignore-missing   # shasum -a 256 on macOS
tar -xzf protean_linux_amd64.tar.gz protean
```

Replace `latest` with a tag such as `v0.1.0` to pin a release. Run the server on Linux; the macOS build is for `secret generate` and `version`. The container image is
`ghcr.io/adnoctem/protean` — see [Container image](#container-image) — and building from source is
`bazel build --config=release //cmd/protean`; see [`docs/CONTRIBUTING.md`](../../docs/CONTRIBUTING.md).

## Quick start

```sh
# 1. Generate a secret. A file is better than an environment variable:
#    /proc/<pid>/environ is readable by the process owner, and environment
#    variables are inherited by child processes.
install -d -m 0700 /etc/protean
protean secret generate > /etc/protean/secret
chmod 0600 /etc/protean/secret

# 2. Start the server. This is the only process that opens the database.
export PROTEAN_SECRET_FILE=/etc/protean/secret
protean server start \
  --listen :8443 \
  --tls-cert /etc/protean/tls/cert.pem \
  --tls-key /etc/protean/tls/key.pem \
  --database /var/lib/protean/db

# 3. In another shell, as the same user, configure it.
protean provider add cf-main --kind cloudflare --zone example.org \
  --set api_token="$CF_TOKEN"
protean provider test cf-main

protean host add dyn.example.org --provider cf-main
protean token create dyn.example.org --label fritzbox
```

The token is printed once. It is stored only as a SHA-256 hash and cannot be recovered; if it is
lost, issue another.

## Configuring a client

protean speaks DynDNS2, so existing clients work unchanged. The username is the hostname and the
password is the token.

```text
https://dyn.example.org:<token>@protean.example.org/nic/update?hostname=dyn.example.org
```

| Client    | Where to put it                                      |
| --------- | ---------------------------------------------------- |
| ddclient  | `protocol=dyndns2`, `server=`, `login=`, `password=` |
| inadyn    | `custom` provider with `ddns-server` and `ddns-path` |
| FRITZ!Box | Internet → Permit Access → DynDNS, "custom" provider |

### FRITZ!Box

Checked against a 7690. Use **Custom** as the provider, and leave the credentials out of the URL:

| Field       | Value                                                                                     |
| ----------- | ----------------------------------------------------------------------------------------- |
| Update URL  | `https://protean.example.org/nic/update?hostname=<domain>&myip=<ipaddr>&myipv6=<ip6addr>` |
| Domain name | `dyn.example.org`                                                                         |
| Username    | anything - it is not checked unless it is itself a hostname                               |
| Password    | the token from `protean token create`                                                     |

The angle brackets are part of the placeholders and the FRITZ!Box substitutes them itself; do not
replace them by hand.

The username is free-form on purpose. A FRITZ!Box has separate Username, Password and Domain name
fields and authenticates with HTTP Basic from the first two, so the username it sends is whatever
you typed there. protean authenticates on the **token**, which belongs to exactly one host and
therefore already identifies which host is being updated. Three shapes all work:

- Username **is** the hostname - what ddclient and inadyn send, and what DynDNS2 conventionally
  implies.
- Username is an account name, and the hostname arrives in `hostname=<domain>` - the FRITZ!Box case
  above.
- Neither is sent, and the token alone identifies the host. Then the update URL needs no
  `hostname=` parameter at all.

A token presented against a _different_ hostname is still refused with `nohost`, so the looser
username does not loosen scoping.

> [!CAUTION] Do not put the token in the update URL
> The FRITZ!Box will happily substitute `<username>` and `<pass>` into a query string, and several
> provider guides tell you to. protean **refuses** credentials sent that way: a token in a URL
> appears in every access log and proxy log it passes through, which is the same exposure the
> plaintext refusal exists to prevent. Put them in the Username and Password fields instead, where
> the FRITZ!Box sends them as HTTP Basic authentication.
>
> Doing it anyway gets `badauth`, and the server log says exactly why.

Parameters, as the [update API](../../docs/ARCHITECTURE.md#update-api) defines them:

| Parameter  | Meaning                                                                                  |
| ---------- | ---------------------------------------------------------------------------------------- |
| `hostname` | FQDN to update. Must match the authenticated host when present.                          |
| `myip`     | IPv4 **or** IPv6 address; `v4,v6` is accepted. Takes precedence over the source address. |
| `myipv6`   | IPv6 address, for clients that send the families separately.                             |

Sending no address at all makes protean use the request's source address.

> [!IMPORTANT] Why you should send `myip` on a DS-Lite connection
> On DS-Lite the IPv4 address protean observes is the ISP's carrier-grade NAT address, not yours.
> An explicit `myip` is the only way protean can learn your real address — and because explicit
> values take precedence, protean refuses an unpublishable one rather than silently substituting
> the CGNAT address it saw.

Return codes are the DynDNS2 ones: `good`, `nochg`, `badauth`, `nohost`, `notfqdn`, `abuse`,
`dnserr`, `911`. protean also sets a matching HTTP status, so failures are visible in a reverse
proxy's access log without parsing bodies; clients read the body and are unaffected.

## TLS

Both modes are supported, and the choice is yours ([TLS and forwarded headers](../../docs/ARCHITECTURE.md#tls-and-forwarded-headers)).
TLS is not optional in either: HTTP Basic sends the token on **every** request.

**Native TLS** — `--tls-cert` and `--tls-key`. The TCP peer is the client, and `X-Forwarded-For` is
ignored entirely.

**Behind a reverse proxy** — leave the TLS flags unset and set `--trusted-proxies`:

```sh
protean server start --listen 127.0.0.1:8080 --trusted-proxies 10.0.0.0/8,127.0.0.1
```

> [!CAUTION] `--trusted-proxies` has no default, and it is security-critical
> In proxy mode that list is the only thing that stops a client choosing its own apparent source
> address — which feeds the per-source rate limiter, the `auth.failed` event, and the address
> written to DNS when `myip` is absent.
>
> With the list set, protean honours `X-Forwarded-For` only from a peer inside it, walking the
> header from the right and skipping trusted hops. It also refuses a plaintext request from a peer
> _outside_ the list, since that request bypassed the proxy and arrived with the token in the clear.
>
> With the list empty, protean cannot tell a proxied request from a direct one, so it ignores the
> headers and warns at startup. Set it.

ACME is not implemented. Use certbot, cert-manager, or the reverse proxy you already have.

## Administration

Everything except `secret generate` and `version` talks to a Unix domain socket. There is no remote
admin API, in any mode. Authorization is the socket's file permissions: it is created `0600`, so
reaching it already requires being the service user or root — and the kernel reports who connected,
via `SO_PEERCRED`, which is what lands in the audit log.

Remote administration means SSH or `docker exec`, then the local CLI.

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

Every list command takes `--json`. Credentials are always redacted, in both forms.

## Providers

Providers are compiled in, so the available kinds are fixed at build time: **cloudflare**,
**route53**, **spaceship**. Adding one is a code change and a rebuild — there is no runtime plugin
loading and no cgo.

```sh
# Cloudflare: a scoped token with Zone.DNS:Write. Add zone_token when the write
# token is scoped to a single zone and so cannot look the zone up by name.
protean provider add cf-main --kind cloudflare --zone example.org \
  --set api_token="$CF_TOKEN" [--set zone_token="$CF_ZONE_TOKEN"]

# Route 53: omit the keys to use the AWS credential chain, which is usually
# what you want on EC2 or EKS and beats copying a long-lived key into the
# database.
protean provider add r53 --kind route53 --zone example.org \
  [--set region=eu-central-1] [--set hosted_zone_id=Z123] \
  [--set access_key_id=... --set secret_access_key=...]

# Spaceship. Note this is not Namecheap's API; a domain at Namecheap itself
# needs a different provider.
protean provider add ss --kind spaceship --zone example.org \
  --set api_key="$KEY" --set api_secret="$SECRET"
```

Use least-privilege credentials — a zone-scoped Cloudflare token, an IAM policy restricted to the
hosted zone. protean cannot verify that: the provider APIs give no way to ask what a credential is
scoped to. It is your responsibility and worth doing.

`provider test` reads the zone to confirm the credentials work. It writes nothing, so it is safe
against a live zone.

## Notifications

protean emits typed events and delivers them over SMTP or HTTP webhooks. Events are persisted
**before** any delivery is attempted, so a relay outage delays notifications rather than dropping
them, and a restart resumes where it left off.

| Event                             | Trigger                                               |
| --------------------------------- | ----------------------------------------------------- |
| `host.updated`                    | an address change was written to the provider         |
| `host.update_failed`              | a provider call failed                                |
| `auth.failed`                     | repeated authentication failures for a host or source |
| `token.created` / `token.revoked` | token lifecycle through the CLI                       |
| `provider.failed`                 | the provider rejected protean's credentials           |

```sh
protean notifier add ops-mail --kind smtp \
  --set host=smtp.example.org --set port=587 \
  --set from=protean@example.org --set to=ops@example.org,oncall@example.org \
  --set username=protean@example.org --set password="$SMTP_PASSWORD"

protean notifier add ops-hook --kind webhook \
  --set url=https://hooks.example.org/t/xxxx

protean notifier test ops-mail
```

Webhooks are HTTPS only and signed with HMAC-SHA256 over the timestamp and body, under
`X-Netory-Signature` and `X-Netory-Timestamp`. The key is derived from the service secret, so a
receiver verifies with the same derivation — see `notify.Verify`. The timestamp is signed so you can
reject a replay.

Delivery is at-least-once: an entry is cleared only after a transport reports success, so a crash in
between replays the event. For mail that is invisible, because `Message-ID` is derived from the
event ID and relays deduplicate on it.

`protean outbox status --pending` shows what is waiting; `--dead` shows what was abandoned after its
retries. Dead entries are kept rather than deleted — a notification that never arrived is exactly
what you go looking for after an incident.

## Backups

```sh
# Take one from the running server. Not stopped, writers not blocked: Badger
# streams at a transaction timestamp, so this is safe on a schedule.
protean backup create --at /var/backups/protean
protean backup create --at s3://my-backups/protean/prod

protean backup list   --at s3://my-backups/protean/prod
protean backup verify protean-20261009T020000Z-1.2.3.backup --at s3://my-backups/protean/prod

# Restore. The server must be STOPPED - see below.
protean backup restore protean-20261009T020000Z-1.2.3.backup \
  --from s3://my-backups/protean/prod --database /var/lib/protean/db
```

A destination is either a directory path or `s3://bucket/prefix`. The local one covers air-gapped
operation and writing a copy next to the service; S3 covers off-host retention.

> [!IMPORTANT] Backups are sealed, and that is not belt-and-braces
> Badger's own backup reads key-value pairs through the normal transaction path, which **decrypts**
> them. A backup of an encrypted database is therefore a plaintext stream of every host, token hash,
> provider credential and notifier password in it, and writing one unsealed would undo the database
> encryption silently.
>
> So every backup is sealed with AES-256-GCM under a key derived from the service secret, under its
> own HKDF label - so a recovered backup key does not open the live database either.
>
> The consequence is worth stating plainly: **a backup is only restorable with the secret that made
> it.** Back the secret up somewhere other than next to the backups.

`create`, `list` and `verify` go through the admin socket, so the **server** does the work. That is
deliberate for S3: the server is the process that already has an instance or task role, and a
plaintext snapshot of every credential in the database has no business crossing a socket when it
does not have to.

S3 credentials come from the AWS credential chain - an instance or task role, the shared config, the
environment - not from anything protean stores. For an S3-compatible server, set `NETORY_S3_ENDPOINT`
and `NETORY_S3_PATH_STYLE=true`.

### Restore is offline, on purpose

`restore` does **not** go through the socket. The server must be stopped, and Badger's exclusive
directory lock enforces that - a restore against a running server fails with a message saying so.

It also refuses a database that already holds data unless given `--force`, because Badger's load
**merges** rather than replaces: keys in the backup overwrite their counterparts and keys absent
from it survive. The result would be neither the backup nor what was there before. Restoring into a
fresh directory is almost always what a restore means.

Because it is offline, `restore` needs the secret - and, for an S3 source, credentials - available to
whoever runs it. On EC2 or EKS that is the same role the server used, so it works unchanged.

### Verifying

`backup verify` downloads a backup and confirms it decrypts. Nothing is restored and nothing
changes, and it exits non-zero on failure, so it belongs in a monitoring check. A backup nobody has
ever opened is a backup nobody knows works, and an incident is the wrong moment to find out.

A systemd timer for nightly backups plus a weekly verification:

```ini
# /etc/systemd/system/protean-backup.service
[Service]
Type=oneshot
User=protean
ExecStart=/usr/local/bin/protean backup create --at s3://my-backups/protean/prod
```

## Runtime settings

These live in the database and take effect without a restart.

```sh
# The whole active configuration at a glance: bootstrap values, runtime
# settings, and what the database holds.
protean config view

protean config list
protean config set ratelimit.per_host 120
protean config set retention.address_history 720h
```

`config view` covers both halves because "what is this server actually doing" is one question.
`config list`, `get` and `set` deal only with the runtime settings - the listen address and the TLS
mode are not settings, so `config get` would never have shown them.

| Setting                         | Default | What it does                                            |
| ------------------------------- | ------- | ------------------------------------------------------- |
| `log.level`                     | —       | overrides the startup log level                         |
| `retention.address_history`     | `2160h` | how long address history is kept; `0` disables it       |
| `ratelimit.per_host`            | `60`    | updates per host per window; `0` disables               |
| `ratelimit.per_source`          | `120`   | requests per source address per window; `0` disables    |
| `ratelimit.window`              | `1h`    | the window both limits are counted over                 |
| `events.auth_failure_threshold` | `5`     | failures before an `auth.failed` event                  |
| `events.dedup_window`           | `0`     | window collapsing identical events; `0` uses one minute |

The 90-day address-history default is a GDPR-relevant setting, not just housekeeping: IP addresses
are personal data. See the [GDPR notes](../../docs/ARCHITECTURE.md#gdpr).

The per-source limit is applied **before** authentication, because its job is to slow down someone
guessing tokens — a limit applied only after a successful authentication would never see them.

## Bootstrap configuration

These are needed before the database can be opened, so they are flags and environment variables
rather than settings. Precedence: defaults, then environment, then flags.

| Flag                | Environment               | Default                     |
| ------------------- | ------------------------- | --------------------------- |
| `--listen`          | `PROTEAN_LISTEN`          | `:8443`                     |
| `--socket`          | `PROTEAN_SOCKET`          | `/run/protean/admin.sock`   |
| `--database`        | `PROTEAN_DATABASE`        | `/var/lib/protean/db`       |
| `--tls-cert`        | `PROTEAN_TLS_CERT`        | unset (proxy mode)          |
| `--tls-key`         | `PROTEAN_TLS_KEY`         | unset (proxy mode)          |
| `--trusted-proxies` | `PROTEAN_TRUSTED_PROXIES` | **empty — see above**       |
| `--log-level`       | `PROTEAN_LOG_LEVEL`       | `info`                      |
| `--log-format`      | `PROTEAN_LOG_FORMAT`      | `text`                      |
| —                   | `PROTEAN_SHUTDOWN_GRACE`  | `15s`                       |
| —                   | `PROTEAN_SECRET`          | —                           |
| —                   | `PROTEAN_SECRET_FILE`     | — (preferred; wins if both) |

The socket path is capped at 106 bytes, because the kernel's `sockaddr_un` holds 108 including its
terminator and protean needs one byte for the atomic-rename staging name.

## Secrets

One high-entropy `PROTEAN_SECRET`, at least 32 bytes after decoding. Everything cryptographic is
derived from it with HKDF-SHA256 under a purpose-specific label — `protean/kv-encryption`,
`protean/webhook-signing` — so a compromised webhook key reveals nothing about the database key. The
raw secret is never handed to a consumer, and never used directly as the Badger encryption key.

`protean secret rotate` is **not implemented**. Re-keying means re-encrypting the whole database, and
how Badger's key registry behaves under re-keying is unverified ([known limitations](../../docs/ARCHITECTURE.md#protean-known-limitations)).
A rotation that half-succeeds leaves a database nothing can open, which is worse than one that has not been
rotated. To rotate by hand, with the server stopped: export,
start with the new secret, re-import.

> [!WARNING] Lose the secret and you lose the database
> It is the only thing that decrypts it. Back it up somewhere other than next to the database.

## Running under systemd

```ini
[Unit]
Description=protean dynDNS control plane
After=network-online.target

[Service]
Type=exec
User=protean
Group=protean
ExecStart=/usr/local/bin/protean server start
Environment=PROTEAN_DATABASE=/var/lib/protean/db
Environment=PROTEAN_SOCKET=/run/protean/admin.sock

# systemd places the secret at %d/secret and protean reads it from there.
LoadCredential=secret:/etc/protean/secret
Environment=PROTEAN_SECRET_FILE=%d/secret

RuntimeDirectory=protean
RuntimeDirectoryMode=0700
StateDirectory=protean
StateDirectoryMode=0700

# The database holds provider credentials and token hashes; protean needs no
# more than its own files and an outbound network.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
# Binding :8443 needs no capability; a port below 1024 would need
# AmbientCapabilities=CAP_NET_BIND_SERVICE.

[Install]
WantedBy=multi-user.target
```

Only one process may open the database. Badger holds an exclusive lock on its directory, so a second
`server start` fails rather than corrupting anything — the constraint is enforced, not just
documented.

## Container image

Published to `ghcr.io/adnoctem/protean` on every release, as a multi-architecture index covering
`linux/amd64` and `linux/arm64`.

```sh
docker pull ghcr.io/adnoctem/protean:1.4.0
```

Every release is tagged with its exact version, and `latest` is moved to the newest one. Pin the
version in anything you deploy; `latest` is for a first look.

What is in the image:

| Property   | Value                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------- |
| base       | `gcr.io/distroless/static-debian12:nonroot`, pinned by digest in `MODULE.bazel`               |
| contents   | `/protean`, mode `0555`, and the base's CA bundle. No shell, no package manager, nothing else |
| user       | `65532:65532`, declared in the image, so nothing has to be overridden to avoid root           |
| entrypoint | `/protean` — the subcommand is the argument                                                   |
| ports      | `8443/tcp`, declared for whoever reads `docker inspect`; it opens nothing by itself           |
| writable   | `/var/lib/protean` and `/run/protean`, both `0700` and owned by `65532`                       |
| size       | about 41 MB                                                                                   |

The CA bundle is why the base is not empty: every provider protean writes to is an HTTPS API, and a
container with no trust roots cannot verify one. It would fail every update with a certificate error
that reads like a misconfiguration and is not one.

### Running it

```sh
docker volume create protean-data

docker run -d --name protean \
  -p 8443:8443 \
  -e PROTEAN_SECRET_FILE=/etc/protean/secret \
  -v /etc/protean/secret:/etc/protean/secret:ro \
  -v protean-data:/var/lib/protean \
  ghcr.io/adnoctem/protean:1.4.0 server start
```

The volume goes on `/var/lib/protean`, not on `/var/lib/protean/db`: the database directory is
created inside it, and mounting one directory keeps a future second directory from needing a second
volume. A fresh Docker volume inherits the mount point's ownership, which the image already sets to
`65532`, so this works without a `chown`. A bind mount does not — a host directory arrives with
whatever it had, and `chown 65532:65532` on it is the fix.

`/run/protean` holds the admin socket and is deliberately not a volume. It is recreated on every
start, and a socket that outlived its server would be a socket nothing is listening on.

> [!WARNING] The volume is worthless without the secret
> The database is encrypted with keys derived from `PROTEAN_SECRET`, so a backed-up volume and a
> lost secret is a backup that opens nothing. Back the secret up separately.

### Administering a running container

The admin socket is a Unix socket inside the container, so admin commands run inside the container:

```sh
docker exec protean /protean config view
docker exec protean /protean provider add cf-main --kind cloudflare --zone example.org \
  --set api_token="$CF_TOKEN"
docker exec protean /protean host add dyn.example.org --provider cf-main
```

There is no shell in the image, so `docker exec -it protean sh` fails. That is the point of a
distroless base: what is in the image is the service, and nothing that would be useful to someone
who got into it. Call the binary directly.

Access to the socket is by file permission — it sits in a `0700` directory owned by `65532` — so the
caller has to be that user or root. `docker exec` runs as the image's user by default, which is the
right one. The audit record names whichever uid connected, so an exec as root is recorded as
`uid=0`.

### Running under Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: protean
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
      app: protean
  template:
    metadata:
      labels:
        app: protean
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        # Makes the persistent volume group-writable by the service user. A
        # freshly provisioned volume is otherwise root-owned, and protean would
        # fail to create its database in it.
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: protean
          image: ghcr.io/adnoctem/protean:1.4.0
          args: ["server", "start"]
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          env:
            - name: PROTEAN_SECRET_FILE
              value: /etc/protean/secret
            - name: PROTEAN_TRUSTED_PROXIES
              value: 10.0.0.0/8
            - name: PROTEAN_LOG_FORMAT
              value: json
          volumeMounts:
            - name: secret
              mountPath: /etc/protean
              readOnly: true
            - name: data
              mountPath: /var/lib/protean
          livenessProbe:
            httpGet: { path: /healthz, port: 8443 }
      volumes:
        - name: secret
          secret:
            secretName: protean
        - name: data
          persistentVolumeClaim:
            claimName: protean
```

One replica, and a `ReadWriteOnce` claim is correct rather than limiting: the database takes a
single writer, so a second replica would not share the load, it would fail to start. Scaling protean
out is not supported, and dynDNS updates are not a workload that needs it.

`/run/protean` is left to the image's own directory rather than mounted, so the manifest sets no
`readOnlyRootFilesystem`. With a policy that requires one, mount an in-memory `emptyDir` at
`/run/protean`; with `fsGroup` already set above, the socket's directory then ends up group-writable
rather than `0700`, which matters only if something else runs in the pod.

```sh
kubectl exec deploy/protean -- /protean host list
```

### Building it yourself

```sh
bazel run   --config=release //cmd/protean:load      # loads protean:dev locally
bazel build --config=release //cmd/protean:tarball   # docker-format tarball, for a registry-less cluster
bazel build --config=release //cmd/protean:image     # the multi-arch index, as an OCI layout
```

`--config=release` is what the published images are built with: it is the difference between the
binary that ships and a debug build nearly twice the size. Leave it off and the image still works,
which is what you want when the reason you are building one is to debug something in it.

`:load` builds the amd64 image only, because loading an index into a Docker engine is not something
it does. The image is defined in [`scripts/bazel/image.bzl`](../../scripts/bazel/image.bzl).

## Operational notes

- **An unchanged address costs nothing.** protean stores the last address written per family and
  answers `nochg` without calling the provider. A router re-sending the same address every five
  minutes is the normal case.
- **`host remove` revokes that host's tokens** but leaves the DNS records alone. protean owns no DNS
  data, and deleting a record you may still want is not its decision.
- **`provider remove` is refused while a host references it.** A host whose provider is gone would
  accept updates and fail to write them, which looks like a DNS outage rather than a configuration
  error.
- **Audit records name the operator**, from the kernel rather than from anything the request
  claimed. Mutations log at info and reads at debug, so a monitoring script polling `host list`
  cannot bury the one `host remove` you are looking for.
- **`/healthz`** touches neither the database nor a provider, so it answers while the service is
  degraded and reports the process itself.

Linux is the only platform protean is supported as a server on. macOS binaries ship as well,
for the subcommands that need no server - `protean secret generate` and `protean version` - which is
what runs on a laptop or in a CI job. No Windows binaries are shipped.
