//go:build linux

package admin

import (
	"net"
	"syscall"
)

// peerOf reads the connecting process's credentials from the kernel via
// SO_PEERCRED.
//
// The kernel records these at connect time from the peer's own process, so the
// caller cannot choose them. That is the entire point: an administrative audit
// record naming a uid the client asserted in a request body would prove
// nothing, while this names the account that actually ran the command.
func peerOf(conn net.Conn) (Peer, bool) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, false
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, false
	}

	var (
		cred    *syscall.Ucred
		credErr error
	)

	// Control runs fn with the fd while holding the connection open, which is
	// the only safe way to touch it - a bare uc.File() would dup the
	// descriptor and leak it.
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return Peer{}, false
	}

	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid, known: true}, true
}

// peerSupported reports that this platform can read peer credentials.
func peerSupported() bool { return true }

// peerUnsupportedReason is empty on Linux.
func peerUnsupportedReason() string { return "" }
