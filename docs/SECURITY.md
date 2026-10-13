# netory Security Policy

## Reporting a Vulnerability

Report suspected vulnerabilities privately to [info+netory@adnoctem.co][report_contact]. Do not open a public issue
with exploit details, credentials or private system information before maintainers have had an opportunity to
assess the report.

Useful reports include:

- The affected service and version (`<service> version`), whether it runs from a release binary or a container
  image, and the image tag or digest.
- The deployment mode - native TLS or behind a reverse proxy, and the `trusted_proxies` setting - and the relevant
  configuration.
- A minimal reproduction using synthetic data, the expected behaviour and the observed behaviour.
- The likely impact, the access required, and whether it is reachable from the network listener or only from the
  admin socket.
- A contact address for follow-up and your disclosure or acknowledgement preferences.

Remove secrets, tokens, client credentials, backend credentials and unrelated personal information from examples
and logs. If a credential has already been exposed, revoke or rotate it at the service that issued it; deleting a
file or log does not invalidate it.

Maintainers will assess the report, discuss reproduction or mitigation as needed, and coordinate a fix and public
disclosure when appropriate. Please coordinate publication while the issue is being addressed. This project is
maintained on a best-effort basis and does not promise a fixed response or remediation deadline.

If a problem originates in a dependency, a DNS provider's API, a backend behind pivot or the container base
image, report it to that project as well, and let netory's maintainers know when a default or a documented
deployment is affected.

## Versions and Fixes

netory is in pre-1.0 development. Fixes target the current development line and are published in a new release;
earlier releases do not receive backports. Minor releases may contain breaking changes - read the release notes
before upgrading.

Pin a release version, or an image digest, for reproducible deployments, and update deliberately to receive fixes.
`latest` tags and `releases/latest` download URLs always move to the newest release.

## Verifying Releases

Every release publishes `CHECKSUMS_SHA256.txt` covering its tarballs, served over HTTPS from GitHub. Verify a
download against it before installing; the service READMEs show how. Checksums detect corruption and tampering in
transit; they do not authenticate the publisher independently of GitHub. Release tarballs and container images are
not signed.

Container images are built from the release tag in CI without a shared build cache, on a distroless base pinned by
digest, and contain the service binary, a CA bundle and nothing else.

## Trust and Privilege Boundaries

- **Admin socket.** Every administrative action, including reading and replacing credentials, goes through each
  service's Unix socket. Access is controlled by file permissions: the service user and root can administer the
  service. Anyone who can execute commands inside a container as either user has full administrative access.
- **Network listeners.** protean authenticates every update with a per-host token. signpost serves anonymous
  reads only and has no network publishing API. pivot authenticates every customer request and forwards only
  `GET`, `HEAD` and `POST`.
- **Reverse proxies.** In proxy mode, `trusted_proxies` decides whose `X-Forwarded-*` headers are believed. An
  over-broad list lets a client choose its apparent address - defeating per-source rate limits and anonymised
  logging - and, for signpost, whether a request counts as encrypted.
- **signpost** distributes code its clients execute without review. Require signed bundles
  (`publish.require_signature`) where publishers can sign, keep the truncation check enabled, and restrict who can
  reach the admin socket. Anyone who can publish can serve arbitrary code to every client of the instance.
- **pivot** is one of two layers. Path rules cannot see data reachable through associations of an allowed entity;
  each customer's backend credential must carry only the permissions that customer needs, and the backend must
  not be reachable by customers directly. Valkey must be on an internal network, with authentication and TLS where
  available; pivot seals sensitive values itself because Valkey stores data in plaintext.
- **Example configuration** under `docs/examples/` is a starting point, not a reviewed policy for any particular
  installation. Read a rule set before applying it.

## Secrets and Diagnostics

- Each service's single secret derives every key it uses. Deliver it as a file, a systemd credential or a
  container secret in preference to an environment variable, and back it up separately from data and backups: an
  encrypted database or a sealed backup cannot be opened without it.
- No secret is accepted as a command-line flag, and `list` and `config view` output redact credentials.
- Logs anonymise client addresses by default. Logs at `debug` level, `full` client addresses and access logs may
  still contain personal data; inspect and redact them before sharing.
- Secret scanning runs on every commit but does not guarantee that every sensitive value is detected.

## Development Environment

Tests generate their secrets with `secret.Generate()` and use synthetic fixtures. The Valkey-backed tests and the
end-to-end suite start containers through the local Docker engine and bind local ports; run them on a trusted
machine. `scripts/release-create.sh` sources code from `LIBSH_DIR`; use a trusted libsh installation of a pinned
release.

<!-- Contact links -->

[report_contact]: mailto:info+netory@adnoctem.co
