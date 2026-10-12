<p align="center">
    <!-- netory -->
    <img src="https://github.com/adnoctem/artwork/blob/8a9d84ca8d91a61bd1f69fdc1ba6362ccbcb5060/projects/netory/icon/netory.svg?raw=true" alt="netory Logo" width="256">
    <h1 align="center">netory</h1>
</p>

[![License](https://img.shields.io/github/license/adnoctem/netory?label=License)][license]
[![go.mod version](https://img.shields.io/github/go-mod/go-version/adnoctem/netory?logo=go)][go]
[![Language](https://img.shields.io/github/languages/top/adnoctem/netory?label=Go&logo=go)][go]
[![Testing](https://github.com/adnoctem/netory/actions/workflows/testing.yaml/badge.svg)][ci_testing_workflow]
[![GitHub Release](https://img.shields.io/github/v/release/adnoctem/netory?label=Release)][github_releases]
[![GitHub Activity](https://img.shields.io/github/commit-activity/m/adnoctem/netory?label=Commits)][github_commits]
[![Bazel](https://img.shields.io/badge/Bazel-built-brightgreen?logo=bazel&logoColor=43A047)][bazel]
[![Renovate](https://img.shields.io/badge/Renovate-enabled-brightgreen?logo=renovate&logoColor=1A1F6C)][renovate]
[![PreCommit](https://img.shields.io/badge/PreCommit-enabled-brightgreen?logo=precommit&logoColor=FAB040)][precommit]

`netory` is an open-source [MIT][license]-licensed collection of three self-hosted network services written in
[Go][go]. Each one is a single static executable with no runtime dependencies, published for Linux and macOS
and as a container image. The project is built using Google's [Bazel][bazel] build system in combination with
their first-party [Gazelle][gazelle] `BUILD` file generator.

## 📖 Overview

Running your own dynamic DNS without handing your zone to yet another provider? [`protean`][protean] accepts
DynDNS2 updates from the clients you already have - routers, ddclient, inadyn - and writes them to the DNS
provider you already use. Serving `curl … | sh` installers? [`signpost`][signpost] publishes them as immutable,
checksummed, optionally signed releases, over HTTPS only, with atomic rollback. Need to let customers into a
production API without letting them reach all of it? [`pivot`][pivot] sits in front of it as a read-only proxy
that issues their credentials, authenticates to the backend on their behalf, filters every request against path
rules, and protects the backend with rate limits, a concurrency cap and a response cache.

## ✨ TL;DR

```shell
# Install one service - protean, signpost or pivot - for linux or darwin, amd64 or arm64
curl -fsSL https://github.com/adnoctem/netory/releases/latest/download/pivot_linux_amd64.tar.gz \
  | tar -xzf - pivot
sudo install -m 0755 pivot /usr/local/bin/pivot

# Or all three at once
curl -fsSL https://github.com/adnoctem/netory/releases/latest/download/netory_linux_amd64.tar.gz \
  | sudo tar -xzf - -C /usr/local/bin protean signpost pivot

# Or run the container image - multi-architecture, distroless, uid 65532
docker run --rm ghcr.io/adnoctem/pivot:latest version
```

Prefer to check what you install first? Every release publishes a checksum file covering every tarball:

```shell
base=https://github.com/adnoctem/netory/releases/latest/download
curl -fsSLO "$base/pivot_linux_amd64.tar.gz"
curl -fsSL "$base/CHECKSUMS_SHA256.txt" | sha256sum -c --ignore-missing
tar -xzf pivot_linux_amd64.tar.gz pivot
```

Linux is the only platform the services are supported on as servers. The macOS builds are for the subcommands
that need no server - `rules validate`, `bundle validate`, `secret generate`, `version` - which is what runs on a
laptop or in a CI job.

## 🛠️ Services

Like most modern [Go][go] projects the executables are located within the [cmd][cmd] directory, each with its
own README documenting how to install, configure, run and operate it. Here's a quick-reference list as an
overview:

- [`protean`][protean]: a self-hosted dynDNS control plane in front of Cloudflare, Route 53 or Spaceship
- [`signpost`][signpost]: a public script router for the one-line install pattern, serving immutable releases
- [`pivot`][pivot]: a transparent, read-only API proxy for letting customers into a production API safely

The reasoning behind each one - its scope, its architecture and every decision that shaped it - is in its
[design document][design].

### 🔃 Contributing

Refer to our [documentation for contributors][contributing] for building and testing, the repository layout,
dependency rules, commit message formats and how a release is made.

### 📥 Maintainers

This project is owned and maintained by [Ad Noctem Collective][org] refer to the [`AUTHORS`][authors] or
[`CODEOWNERS`][owners] for more information. You may also use the linked contact details to reach out directly.

### ©️ Copyright

- _Assets provided by:_ **[IconScout](https://iconscout.com)**
- _Sources provided by:_ **[Ad Noctem Collective][org]** under the **[MIT License][license]**

<!-- INTERNAL REFERENCES -->

<!-- Project references -->

[cmd]: cmd
[protean]: cmd/protean
[signpost]: cmd/signpost
[pivot]: cmd/pivot

<!-- File references -->

[license]: LICENSE
[contributing]: docs/CONTRIBUTING.md
[design]: docs/design
[authors]: .github/AUTHORS
[owners]: .github/CODEOWNERS
[ci_testing_workflow]: https://github.com/adnoctem/netory/actions/workflows/testing.yaml

<!-- General links -->

[org]: https://github.com/adnoctem
[go]: https://go.dev
[bazel]: https://bazel.build
[gazelle]: https://github.com/bazelbuild/bazel-gazelle
[github_releases]: https://github.com/adnoctem/netory/releases
[github_commits]: https://github.com/adnoctem/netory/commits/main/

<!-- Third-party -->

[renovate]: https://renovatebot.com/
[precommit]: https://pre-commit.com/
