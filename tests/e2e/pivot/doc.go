// Package pivot holds the end-to-end test that runs the real pivot binary
// against a real Valkey and a backend that behaves like the one it is designed
// to front.
//
// # What it is for
//
// The unit tests exercise the pipeline through an in-process handler, which
// covers the logic and misses three things that have broken real deployments
// of services shaped like this one: the binary's own flag and environment
// wiring, the CLI that an operator actually types, and the behaviour of two
// replicas sharing one store. This test runs all three for real - two `pivot
// server start` processes, configured only through `pivot` subcommands over
// their admin sockets, driven over HTTP.
//
// It is also what verifies the Shopware example. That rule set is written against known CVEs rather than against an enumerated
// route list, so what can be verified without deploying Shopware itself is
// that the documented example behaves as intended against a backend speaking the Admin
// API's shapes: its oauth2 token endpoint, its entity routes, and its search
// endpoints. Deploying Shopware and MySQL to check a path list would be a
// different and much slower test, and Shopware is the reference backend rather
// than the point - the same test therefore covers the api-key and http-basic
// backend modes, which no Shopware deployment would exercise at all.
//
// # Running it
//
// The test is behind the `e2e` build tag and is skipped by default. It needs a
// Docker daemon, a Go toolchain (it builds the binary under test) and about
// 20 MB of image pull on a cold cache:
//
//	go test -tags e2e -timeout 10m ./tests/e2e/pivot/...
//
// Set PIVOT_E2E_VALKEY to an address to use an existing Valkey instead of
// starting a container, which turns local iteration into one `docker run` and
// then as many fast runs as you like.
//
// On a machine whose Docker credential helper is unreachable - a WSL shell
// against Docker Desktop, for instance - testcontainers can fail to pull its
// own reaper image. `DOCKER_CONFIG` pointing at a directory holding an empty
// `{}` config works around it without touching the real one.
//
// # Conventions
//
// Not in the Bazel build. The root BUILD file excludes this directory, because
// the test needs a Docker socket and a Go toolchain inside what would be a
// hermetic sandbox, and `bazel test //...` promising to run it while silently
// skipping it would be worse than not offering it.
//
// This package is not parallel-safe: there is one stack per `go test`
// invocation and no test here calls t.Parallel.
//
// This file carries no build tag on purpose. A package whose every file is
// excluded by a constraint makes `go build ./...` fail with "build constraints
// exclude all Go files", which would break both the go-build-repo-mod
// pre-commit hook and the `go vet ./...` step in CI.
package pivot
