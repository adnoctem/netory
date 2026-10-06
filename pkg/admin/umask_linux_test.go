//go:build linux

package admin_test

import "syscall"

// setUmask sets the process umask and returns the previous value. It is
// process-global, so the tests using it must not run in parallel with anything
// that creates files.
func setUmask(mask int) int { return syscall.Umask(mask) }
