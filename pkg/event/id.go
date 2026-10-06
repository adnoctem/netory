package event

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// IDLen is the length of an event ID in characters.
const IDLen = 32

// NewID returns a unique, lexicographically sortable event ID for an event that
// occurred at t.
//
// The layout is 16 hex characters of Unix nanoseconds followed by 16 of
// randomness. Fixed-width hex is what makes it sort: the outbox is scanned by
// key prefix, and Badger iterates in byte order, so an ID that sorts
// chronologically means a restart replays pending events in roughly the order
// they happened without a secondary index to maintain.
//
// This is deliberately not a ULID from a library. The property needed here is
// "fixed-width, time-ordered, unique", which fixed-width hex gives in a few
// lines; a dependency would have to be justified against the standard library,
// and Crockford base32's shorter output is not a justification.
//
// Uniqueness rests on the random half. Two events in the same nanosecond get
// arbitrary relative order, which is correct - they are simultaneous.
func NewID(t time.Time) string {
	var buf [16]byte

	// Unix nanoseconds, big-endian so the byte order matches the numeric
	// order. This overflows in the year 2262, which is not a constraint worth
	// designing around.
	binary.BigEndian.PutUint64(buf[0:8], uint64(t.UnixNano()))

	// crypto/rand.Read never returns an error; it panics on an unusable system
	// source, which is not a condition this package could recover from anyway.
	_, _ = rand.Read(buf[8:16])

	return hex.EncodeToString(buf[:])
}

// TimeFromID recovers the timestamp encoded in an ID. The second result is
// false when the ID is not one this package generated.
func TimeFromID(id string) (time.Time, bool) {
	if len(id) != IDLen {
		return time.Time{}, false
	}

	raw, err := hex.DecodeString(id[:16])
	if err != nil {
		return time.Time{}, false
	}

	return time.Unix(0, int64(binary.BigEndian.Uint64(raw))).UTC(), true
}
