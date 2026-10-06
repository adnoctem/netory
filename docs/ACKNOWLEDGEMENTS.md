# netory source acknowledgements

This records where netory's conventions, formats and reference data came from, distinguishing work
adapted from a sibling project, formats implemented from a public specification, and sources
consulted as evidence. Upstream licence notices and source comments remain authoritative for the
material they cover; a similar name alone is not evidence of shared provenance.

## Adapted work

- The repository layout, the Bazel/Bzlmod harness and the release script's shape follow
  [adnoctem/gopskit](https://github.com/adnoctem/gopskit), which all three design documents name as
  the reference for conventions. The container build in [`scripts/bazel/image.bzl`](../scripts/bazel/image.bzl)
  follows the setup gopskit introduced for its cluster bridge - static binary per architecture
  through platform transitions, combined into a multi-arch index by rules_oci, with `:load` for
  local use and `:push` for the registry. Two things differ, and both are recorded in that file: the
  base is not empty, because all three services make outbound TLS calls and need a CA bundle, and
  the images declare the state directories their services write to.
- `scripts/release-create.sh` is built on [adnoctem/libsh](https://github.com/adnoctem/libsh), the
  shared Bash library, and follows the shape gopskit's scripts use: libsh's option parser, its
  logging and its prerequisite checks instead of a local copy of each, with libsh's own
  `<domain>-<verb>[-<object>].sh` naming and function-comment convention. libsh is installed on the
  machine rather than vendored, and pinned, because it is 0.x and says so.
- The CI and publishing conventions follow
  [adnoctem/substrate](https://github.com/adnoctem/substrate): a release that only happens when a
  repository variable opens the gate and somebody dispatches it, a tested-commit check that refuses
  a branch which has moved on, a bootstrap path for the first `0.1.0` because semantic-release
  cannot produce it, retention of the prepared release so a partial publication can be finished
  rather than rebuilt, and the 0.x policy in which a breaking change takes the minor version.
  `docs/AGENTS.md` with a root symlink, and `docs/CONTRIBUTING.md` beside it, are substrate's
  arrangement as well.

## Formats implemented from their specifications

- `internal/signpost/bundle/minisign.go` verifies the signature format of
  [jedisct1/minisign](https://github.com/jedisct1/minisign), implemented from the published format
  over the standard library's `crypto/ed25519` rather than by taking a dependency. Only BLAKE2b
  comes from outside, through `golang.org/x/crypto`, because modern minisign prehashes and Go has no
  BLAKE2b in its standard library. signpost verifies and never signs; signing is the operator's own
  `minisign` CLI.
- protean speaks DynDNS2, the de facto update protocol existing dynDNS clients already implement, so
  that ddclient, inadyn and consumer routers work against it unchanged.
- pivot's token endpoint emulates the client-credentials grant of
  [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), down to the error bodies of §5.1 and §5.2, so
  that a client written against the backend's own documentation needs no change. Its path
  normalisation follows
  [RFC 3986 §6.2.2.2](https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.2), decoding only the
  unreserved set - with the deliberate difference, recorded in
  `internal/pivot/rules/normalize.go`, that an ambiguous path is refused rather than cleaned.

## Reference data and evidence

- The minisign compatibility test vector in `internal/signpost/bundle/testdata/` is a genuine signed
  artifact from minisign's own 0.12 release, verified against the public key published in minisign's
  README. Its provenance and the reason a round-trip test would not have been enough are recorded in
  that directory's `README.md`.
- pivot's documented `shopware-readonly` example refuses routes whose history is the argument for
  refusing them:
  [CVE-2026-48014](https://osv.dev/vulnerability/CVE-2026-48014) (order state transitions),
  [CVE-2026-48008](https://github.com/advisories/GHSA-gv8p-48fr-4fxg) (the Sync API) and
  [shopware/shopware#20828](https://github.com/shopware/shopware/issues/20828) (version routes).
  Each denial carries the identifier in its comment, so `pivot rules test` answers why. Shopware is
  the reference backend rather than the point; nothing in pivot itself knows what Shopware is, and
  the example is a file an operator reads and edits rather than something the binary installs.
- The FRITZ!Box guidance in [`cmd/protean/README.md`](../cmd/protean/README.md) was checked by hand
  against a 7690. Other clients' settings come from their own documentation.

## Dependencies

[`go.mod`](../go.mod) and [`MODULE.bazel`](../MODULE.bazel) are the authoritative list, and every
dependency keeps its own licence. Four are worth naming because netory depends on their behaviour
rather than only their API, which is why each has a test that would catch a change in it:

- [Badger](https://github.com/dgraph-io/badger) - the store behind protean and signpost, including
  its encryption at rest. `pkg/kv/badgerkv` relies on behaviour its API does not document, notably
  that `Entry.WithTTL` truncates expiry to whole seconds.
- [valkey-go](https://github.com/valkey-io/valkey-go) - pivot's Valkey client, chosen because it is
  pure Go. Valkey's own GLIDE client links a C library and so cannot be released here.
- [libdns](https://github.com/libdns/libdns), with `libdns/cloudflare` and `libdns/route53` - the
  adapter protean's Cloudflare and Route 53 providers sit behind. Spaceship has no libdns package,
  so `internal/protean/provider/spaceship.go` speaks its published HTTP API at
  `https://spaceship.dev/api/v1` directly. It is not Namecheap's API: a domain held at Namecheap
  itself needs a different provider.
- [testcontainers-go](https://github.com/testcontainers/testcontainers-go) - test-only; it owns the
  container lifecycle in the end-to-end suites, which is what makes the same command work locally
  and in CI.

`scripts/release-create.sh` additionally needs [libsh](https://github.com/adnoctem/libsh) on the
machine, which is not a Go dependency and so appears in neither file; CI installs a pinned version.

The container images are built on
[distroless](https://github.com/GoogleContainerTools/distroless)'s `static-debian12` base, pinned by
digest.
