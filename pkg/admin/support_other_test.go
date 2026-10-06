//go:build !linux

package admin_test

// peerCredentialsSupported is false where SO_PEERCRED is unavailable.
const peerCredentialsSupported = false
