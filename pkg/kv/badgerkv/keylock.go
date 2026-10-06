package badgerkv

import (
	"hash/maphash"
	"sync"
)

// keyLockShards is the number of mutexes in the table. A collision costs two
// unrelated keys a little serialisation and nothing else, so the table is
// sized to make collisions rare rather than impossible - which is what lets it
// be a fixed array with no allocation, no map and no reference counting to get
// wrong.
const keyLockShards = 512

// keyLocks serialises the read-modify-write operations - Increment,
// CompareAndSwap and SetIfAbsent - on a per-key basis.
//
// This is emphatically not a return of gopskit's global mutex, which wraps
// every Get and every Set and so reduces the whole store to one goroutine at a
// time. Get, Set, Delete, Keys and Scan take no lock here at all; only the
// three operations that read a value and then write a value derived from it
// do, and only against other operations on the same key.
//
// Badger does detect these conflicts on its own and rejects the loser with
// ErrConflict, so the retry loop alone is correct. It is not, however,
// adequate: with eight goroutines incrementing one counter, at most one
// transaction commits per round, and the rest burn a retry each. The retry
// budget is exhausted long before the work is done and increments are lost.
// Taking the key's lock first means the transactions queue instead of
// colliding, so Badger sees no conflict at all and the retry loop becomes the
// backstop it was meant to be - for the genuine remaining case of a plain Set
// racing a read-modify-write on the same key.
//
// This is sound because Badger is single-process by construction: it holds an
// exclusive lock on its directory, so every writer to this database is a
// goroutine in this process. The Valkey implementation needs no equivalent,
// since it has server-side atomic primitives (INCRBY, SET NX, and a script for
// compare-and-swap) and spans replicas, where an in-process lock would mean
// nothing anyway.
type keyLocks struct {
	seed   maphash.Seed
	shards [keyLockShards]sync.Mutex
}

func newKeyLocks() *keyLocks {
	return &keyLocks{seed: maphash.MakeSeed()}
}

// lock acquires the mutex guarding key and returns its release function.
func (k *keyLocks) lock(key []byte) func() {
	m := &k.shards[maphash.Bytes(k.seed, key)%keyLockShards]
	m.Lock()

	return m.Unlock
}
