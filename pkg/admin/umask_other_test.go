//go:build !linux

package admin_test

// setUmask is a no-op where syscall.Umask is unavailable. The assertion it
// supports is about Linux behaviour, and Linux is the only supported platform.
func setUmask(int) int { return 0 }
