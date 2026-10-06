//go:build linux

package admin_test

// peerCredentialsSupported mirrors the build constraint on peer_linux.go, so
// the peer assertions are real on the supported platform and skipped rather
// than silently weakened elsewhere.
const peerCredentialsSupported = true
