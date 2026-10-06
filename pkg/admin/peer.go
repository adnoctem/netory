package admin

import (
	"context"
	"os/user"
	"strconv"
)

// Peer is the identity of the process on the other end of an admin connection,
// as reported by the kernel rather than claimed by the client.
//
// The zero Peer means "not known", which is the honest answer on a platform
// without SO_PEERCRED. Callers check Known rather than testing UID against
// zero, since uid 0 is root and a perfectly real answer.
type Peer struct {
	UID uint32
	GID uint32
	PID int32

	known bool
}

// Known reports whether the kernel supplied credentials for this connection.
func (p Peer) Known() bool { return p.known }

// Username resolves the peer's uid to an account name, falling back to the
// numeric uid when it cannot be resolved - a uid with no passwd entry is
// normal in a container.
func (p Peer) Username() string {
	if !p.known {
		return "unknown"
	}

	uid := strconv.FormatUint(uint64(p.UID), 10)
	if u, err := user.LookupId(uid); err == nil && u.Username != "" {
		return u.Username
	}

	return uid
}

// String renders the peer for an audit record.
func (p Peer) String() string {
	if !p.known {
		return "unknown"
	}

	return p.Username() + "(uid=" + strconv.FormatUint(uint64(p.UID), 10) +
		" pid=" + strconv.FormatInt(int64(p.PID), 10) + ")"
}

// peerContextKey is unexported so no other package can plant a forged Peer in a
// request context.
type peerContextKey struct{}

// PeerFrom returns the Peer for the connection that carried r's context. The
// second result is false when the platform could not supply credentials.
func PeerFrom(ctx context.Context) (Peer, bool) {
	p, ok := ctx.Value(peerContextKey{}).(Peer)

	return p, ok && p.known
}

// withPeer attaches a Peer to a connection's base context.
func withPeer(ctx context.Context, p Peer) context.Context {
	return context.WithValue(ctx, peerContextKey{}, p)
}
