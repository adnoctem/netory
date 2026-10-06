//go:build !linux

package admin

import "net"

// peerOf reports no credentials on platforms without SO_PEERCRED.
//
// Linux is the only supported server platform for all three services; macOS is
// best-effort so that the test suite and local development work there. The
// consequence is that an audit record made on a non-Linux host says the peer is
// unknown, rather than guessing - which is why Peer.Known exists and why the
// audit log renders "peer=unknown" instead of "uid=0".
func peerOf(net.Conn) (Peer, bool) { return Peer{}, false }

// peerSupported reports that this platform cannot read peer credentials.
func peerSupported() bool { return false }

// peerUnsupportedReason explains the gap for a startup warning.
func peerUnsupportedReason() string {
	return "SO_PEERCRED is Linux-only, so administrative actions will be audited without a peer identity"
}
