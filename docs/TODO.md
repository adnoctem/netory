# ✅ TODOs - `netory`

## ➕ Additions

- [ ] Serve netory's own JSON Schemas through `signpost`, as a bundle whose routes match the schemas' `$id` paths,
      and point `pkg/schema.BaseURL` at that host. The documented examples under `docs/examples/` could join the
      same bundle.
- [ ] `pivot secret rotate`: re-seal stored backend and notifier credentials under a new secret across all
      replicas, instead of refusing.
- [ ] `protean secret rotate` and `signpost secret rotate`, once Badger's key-registry behaviour under re-keying is
      verified (see below).

## ✏️ Planned Changes

- [ ] Verify against a live Spaceship account whether `PUT /dns/records/{domain}` replaces an existing record set.
      If it does, drop the delete-before-save in `internal/protean/provider/spaceship.go` and the brief window in
      which a name does not resolve during an update.
- [ ] Verify how Badger's key registry handles re-keying an encrypted database, as the prerequisite for rotating
      `PROTEAN_SECRET` and `SIGNPOST_SECRET` in place.
- [ ] Remove the Release workflow's `bootstrap` input now that `v0.1.0` exists, and narrow the Checkov `CKV_GHA_7`
      suppression in `.github/linters/.checkov.yaml` to the remaining `sha` input.
- [ ] Accept duration strings such as `"1m"` for a route's `ttl` in JSON rule documents, as YAML already does, with
      a duration type that unmarshals both forms; regenerate `docs/schema/pivot-rules-v1.json` with it.
- [ ] Update `cycjimmy/semantic-release-action` from v7.1.2 to v8 once v8 has a patch release.
- [ ] Check `docs/examples/pivot/shopware-readonly.yaml` against the complete Admin API route list of a target
      Shopware version; it is exercised against the API's request shapes only.

## 💡 Ideas

- [ ] Homebrew tap with an umbrella `netory` formula and `netory-<service>` formulae, pending the choice between
      shell installers and a tap across Ad Noctem repositories. A tap reference cannot have more than three
      components, so `adnoctem/tap/netory/pivot` is not possible; verify Homebrew's Tap Trust behaviour for
      fully-qualified installs on macOS before documenting one.
- [ ] Detect the operating system and architecture in the README's one-line install instead of naming
      `linux_amd64`.
- [ ] A chunked backup format for `protean`, lifting the 1 GiB in-memory limit on a sealed backup.
- [ ] An S3 content backend for `signpost` behind its existing storage interface.

## 🔗 Links

- [Releases](https://github.com/adnoctem/netory/releases)
- [Container images](https://github.com/orgs/adnoctem/packages?repo_name=netory)
- [libsh](https://github.com/adnoctem/libsh)
