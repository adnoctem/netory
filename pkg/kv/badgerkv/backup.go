package badgerkv

import (
	"errors"
	"fmt"
	"io"

	"github.com/dgraph-io/badger/v4"

	"github.com/adnoctem/netory/pkg/kv"
)

// restorePendingWrites is how many write batches Load applies in parallel.
// Badger's own examples use 256; a restore is a one-off and not latency
// sensitive, so there is nothing to tune here.
const restorePendingWrites = 256

// Backup writes a consistent snapshot of the database to w.
//
// It runs against a live database: Badger streams at a transaction timestamp,
// so the snapshot is consistent without stopping the server or blocking
// writers. That is what makes a scheduled backup of a running service possible.
//
// > The stream is PLAINTEXT, even when the database is encrypted.
//
// Badger reads key-value pairs through the normal transaction path, which
// decrypts them, so the bytes written here are every host, token hash, provider
// credential and notifier password in the clear. Callers must seal the result -
// see pkg/backup - and no caller should ever write this directly to a file or a
// bucket. The method name says "Backup" rather than something more alarming
// because it is the right name; this comment is the warning.
func (s *Store) Backup(w io.Writer) (uint64, error) {
	if s.closed.Load() {
		return 0, kv.ErrClosed
	}

	// since=0 takes everything. Incremental backups would need the caller to
	// persist the returned version and would produce a chain that is only as
	// good as its weakest link; for a database this size a full backup every
	// time is simpler and strictly safer.
	version, err := s.db.Backup(w, 0)
	if err != nil {
		return 0, fmt.Errorf("badgerkv: back up the database: %w", err)
	}

	return version, nil
}

// Restore loads a backup stream into the database.
//
// Badger's Load merges rather than replaces: keys in the backup overwrite their
// counterparts and keys absent from it are left alone. That is almost never
// what a restore means, so callers are expected to restore into an empty
// database - IsEmpty exists for that check, and the protean CLI refuses a
// non-empty one unless told otherwise.
func (s *Store) Restore(r io.Reader) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}

	if err := s.db.Load(r, restorePendingWrites); err != nil {
		return fmt.Errorf("badgerkv: restore the database: %w", err)
	}

	return nil
}

// IsEmpty reports whether the database holds no keys at all.
//
// Used to decide whether a restore would merge into existing data rather than
// populate a fresh database.
func (s *Store) IsEmpty() (bool, error) {
	if s.closed.Load() {
		return false, kv.ErrClosed
	}

	empty := true
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()

		it.Rewind()
		empty = !it.Valid()

		return nil
	})
	if err != nil {
		if errors.Is(err, badger.ErrDBClosed) {
			return false, kv.ErrClosed
		}

		return false, fmt.Errorf("badgerkv: check whether the database is empty: %w", err)
	}

	return empty, nil
}
