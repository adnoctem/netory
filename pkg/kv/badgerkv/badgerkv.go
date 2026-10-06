// Package badgerkv implements kv.Store on top of BadgerDB.
//
// It is the store for protean and signpost, both of which are single-replica
// services whose server process is the only database owner: Badger holds an
// exclusive directory lock, so a second process cannot open the same directory
// while the server runs. That is what makes "one binary, one database owner"
// an enforced constraint rather than a documented convention, and why the CLI
// subcommands talk to the admin socket instead of opening the store.
package badgerkv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/log"
)

// separator joins a namespace and a key into the physical Badger key. The
// namespace charset enforced by kv.ValidateNamespace excludes this byte, so
// splitting a physical key back apart is unambiguous.
const separator = '/'

const (
	// DefaultDiscardRatio is the fraction of a value-log file that must be
	// reclaimable before Badger rewrites it.
	DefaultDiscardRatio = 0.7

	// DefaultGCInterval is how often the background value-log collector runs.
	// Badger does not reclaim value-log space on its own, so without this a
	// long-running server's disk use only grows - which matters most for
	// exactly the data that churns: the notification outbox and, in protean,
	// expiring address history.
	DefaultGCInterval = 10 * time.Minute

	// encryptedIndexCacheSize is the index cache Badger requires when an
	// encryption key is set. Badger refuses to open an encrypted database with
	// a zero index cache, because it would have to decrypt index blocks on
	// every single read.
	encryptedIndexCacheSize = 64 << 20 // 64 MiB
)

// Options configures a Store. The zero value is not usable: either Path or
// InMemory must be set.
type Options struct {
	// Path is the database directory. It is created if missing. Leave empty
	// when InMemory is set.
	Path string

	// InMemory keeps the whole database in memory, discarding it on Close.
	// This is what tests use instead of a separate mock implementation, so the
	// code under test exercises the same store the server runs on.
	InMemory bool

	// EncryptionKey enables encryption at rest. It must be 16, 24 or 32 bytes;
	// everything in netory derives 32 bytes (AES-256) from the service secret
	// via HKDF, and the raw secret is never passed here.
	EncryptionKey []byte

	// Logger receives Badger's own diagnostics. When nil, Badger's logging is
	// disabled rather than left pointed at stderr in its own format.
	Logger *log.Logger

	// DiscardRatio overrides DefaultDiscardRatio for value-log GC.
	DiscardRatio float64

	// GCInterval overrides DefaultGCInterval. A negative value disables the
	// background collector, which in-memory stores do automatically since
	// Badger has no value log to collect.
	GCInterval time.Duration
}

// Store is a kv.Store backed by BadgerDB.
//
// Note what is not here: no current namespace, and no mutex around the
// operations. gopskit's Database guards every read and write with one global
// sync.Mutex, which serialises the entire store down to a single goroutine.
// That lock existed to protect the mutable namespace field; with the namespace
// passed per call, there is nothing left for it to protect, and Badger's own
// MVCC and conflict detection handle concurrency properly.
type Store struct {
	db   *badger.DB
	opts badger.Options

	// closed is checked at the top of every operation so a use-after-Close is
	// kv.ErrClosed rather than badger.ErrDBClosed leaking through.
	closed atomic.Bool

	// keyLocks serialises the read-modify-write operations per key. See
	// keylock.go for why this is not gopskit's global mutex returning.
	keyLocks *keyLocks

	// gcStop ends the background collector; gcDone waits for it, so Close
	// cannot race the collector into a closed database.
	gcStop chan struct{}
	gcDone chan struct{}

	closeOnce sync.Once
}

// enforce implementation of the interface
var _ kv.Store = (*Store)(nil)

// New opens a Badger database and returns it as a kv.Store.
func New(opts Options) (*Store, error) {
	if opts.InMemory && opts.Path != "" {
		return nil, fmt.Errorf("badgerkv: Path and InMemory are mutually exclusive, got path %q", opts.Path)
	}

	if !opts.InMemory && opts.Path == "" {
		return nil, errors.New("badgerkv: either Path or InMemory must be set")
	}

	bOpts := badger.DefaultOptions(opts.Path).
		WithInMemory(opts.InMemory).
		WithLogger(newBadgerLogger(opts.Logger))

	if len(opts.EncryptionKey) > 0 {
		switch len(opts.EncryptionKey) {
		case 16, 24, 32:
		default:
			return nil, fmt.Errorf(
				"badgerkv: encryption key is %d bytes, Badger accepts 16, 24 or 32 - derive it with pkg/secret rather than passing the service secret directly",
				len(opts.EncryptionKey),
			)
		}

		bOpts = bOpts.
			WithEncryptionKey(opts.EncryptionKey).
			WithIndexCacheSize(encryptedIndexCacheSize)
	}

	if !opts.InMemory {
		// Badger creates its own files but not the directory holding them.
		// 0700 rather than 0755: the database holds provider credentials,
		// notifier passwords and token hashes, and only the service user has
		// any business reading them.
		if err := os.MkdirAll(opts.Path, 0o700); err != nil {
			return nil, fmt.Errorf("badgerkv: create database directory %q: %w", opts.Path, err)
		}
	}

	db, err := badger.Open(bOpts)
	if err != nil {
		return nil, fmt.Errorf("badgerkv: open database at %q: %w", opts.Path, err)
	}

	s := &Store{db: db, opts: bOpts, keyLocks: newKeyLocks()}
	s.startGC(opts)

	return s, nil
}

// Path returns the database directory, empty for an in-memory store. It is
// deliberately on the concrete type and not on kv.Store, which no Valkey
// implementation could answer.
func (s *Store) Path() string { return s.opts.Dir }

// Options returns the badger.Options the database was opened with, for
// reference rather than reconfiguration.
func (s *Store) Options() badger.Options { return s.opts }

// Get implements kv.Store.
func (s *Store) Get(ctx context.Context, ns, key string) ([]byte, error) {
	if err := s.precheck(ctx, ns, key); err != nil {
		return nil, err
	}

	var out []byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(physical(ns, key))
		if err != nil {
			return err
		}

		out, err = item.ValueCopy(nil)

		return err
	})
	if err != nil {
		return nil, s.translate(err, "get", ns, key)
	}

	return out, nil
}

// Set implements kv.Store.
func (s *Store) Set(ctx context.Context, ns, key string, value []byte, opts ...kv.SetOption) error {
	if err := s.precheck(ctx, ns, key); err != nil {
		return err
	}

	o := kv.ResolveSetOptions(opts...)
	err := s.db.Update(func(txn *badger.Txn) error {
		return txn.SetEntry(entry(ns, key, value, o))
	})
	if err != nil {
		return s.translate(err, "set", ns, key)
	}

	return nil
}

// Has implements kv.Store.
//
// It asks Badger for the item and discards the value, rather than reading the
// value and testing its length as gopskit does - under that approach a key
// deliberately stored with an empty value reports as absent.
func (s *Store) Has(ctx context.Context, ns, key string) (bool, error) {
	if err := s.precheck(ctx, ns, key); err != nil {
		return false, err
	}

	err := s.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(physical(ns, key))

		return err
	})
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, badger.ErrKeyNotFound):
		return false, nil
	default:
		return false, s.translate(err, "has", ns, key)
	}
}

// Delete implements kv.Store. Deleting an absent key succeeds: Badger's
// txn.Delete writes a tombstone without checking for a prior value.
func (s *Store) Delete(ctx context.Context, ns, key string) error {
	if err := s.precheck(ctx, ns, key); err != nil {
		return err
	}

	err := s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(physical(ns, key))
	})
	if err != nil {
		return s.translate(err, "delete", ns, key)
	}

	return nil
}

// Keys implements kv.Store.
func (s *Store) Keys(ctx context.Context, ns, prefix string) ([]string, error) {
	if err := s.precheckPrefix(ctx, ns, prefix); err != nil {
		return nil, err
	}

	var keys []string
	err := s.iterate(ns, prefix, false, func(key string, _ *badger.Item) error {
		keys = append(keys, key)

		return nil
	})
	if err != nil {
		return nil, s.translate(err, "keys", ns, prefix)
	}

	return keys, nil
}

// Scan implements kv.Store.
func (s *Store) Scan(ctx context.Context, ns, prefix string, fn func(kv.Entry) error) error {
	if err := s.precheckPrefix(ctx, ns, prefix); err != nil {
		return err
	}

	if fn == nil {
		return errors.New("badgerkv: Scan requires a non-nil callback")
	}

	err := s.iterate(ns, prefix, true, func(key string, item *badger.Item) error {
		// The value handed to fn is only valid for the duration of the call,
		// which is what kv.Store.Scan documents. item.Value avoids the copy
		// ValueCopy would make on every single entry.
		var ferr error
		if err := item.Value(func(v []byte) error {
			ferr = fn(kv.Entry{Key: key, Value: v})

			return nil
		}); err != nil {
			return err
		}

		return ferr
	})

	switch {
	case err == nil, errors.Is(err, kv.ErrStopIteration):
		return nil
	default:
		return err
	}
}

// SetIfAbsent implements kv.Store. The read and the write share one
// transaction, so Badger's conflict detection rejects a concurrent writer that
// got there first and the retry loop re-reads.
func (s *Store) SetIfAbsent(ctx context.Context, ns, key string, value []byte, opts ...kv.SetOption) (bool, error) {
	if err := s.precheck(ctx, ns, key); err != nil {
		return false, err
	}

	defer s.keyLocks.lock(physical(ns, key))()

	o := kv.ResolveSetOptions(opts...)
	wrote := false
	err := s.retry(ctx, func(txn *badger.Txn) error {
		wrote = false

		_, err := txn.Get(physical(ns, key))
		switch {
		case err == nil:
			return nil // present, leave it alone
		case !errors.Is(err, badger.ErrKeyNotFound):
			return err
		}

		if err := txn.SetEntry(entry(ns, key, value, o)); err != nil {
			return err
		}
		wrote = true

		return nil
	})
	if err != nil {
		return false, s.translate(err, "set-if-absent", ns, key)
	}

	return wrote, nil
}

// CompareAndSwap implements kv.Store.
func (s *Store) CompareAndSwap(
	ctx context.Context, ns, key string, expected, value []byte, opts ...kv.SetOption,
) (bool, error) {
	if err := s.precheck(ctx, ns, key); err != nil {
		return false, err
	}

	defer s.keyLocks.lock(physical(ns, key))()

	o := kv.ResolveSetOptions(opts...)
	wrote := false
	err := s.retry(ctx, func(txn *badger.Txn) error {
		wrote = false

		item, err := txn.Get(physical(ns, key))
		switch {
		case errors.Is(err, badger.ErrKeyNotFound):
			return nil // absent is never an implicit create
		case err != nil:
			return err
		}

		current, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}

		// Plain equality, not a constant-time compare: the values here are
		// opaque state, and nothing about a CAS outcome is a secret. Token
		// comparison is a different concern and lives in the services.
		if !bytes.Equal(current, expected) {
			return nil
		}

		if err := txn.SetEntry(entry(ns, key, value, o)); err != nil {
			return err
		}
		wrote = true

		return nil
	})
	if err != nil {
		return false, s.translate(err, "compare-and-swap", ns, key)
	}

	return wrote, nil
}

// Increment implements kv.Store.
//
// Badger has no native counter, so this is a read-modify-write inside one
// transaction. Badger tracks the key as read, so two concurrent increments
// cannot both commit - the loser gets badger.ErrConflict and retries, which is
// what makes the result correct under contention rather than merely likely.
func (s *Store) Increment(ctx context.Context, ns, key string, delta int64, opts ...kv.SetOption) (int64, error) {
	if err := s.precheck(ctx, ns, key); err != nil {
		return 0, err
	}

	defer s.keyLocks.lock(physical(ns, key))()

	o := kv.ResolveSetOptions(opts...)
	var next int64
	err := s.retry(ctx, func(txn *badger.Txn) error {
		current := int64(0)

		item, err := txn.Get(physical(ns, key))
		switch {
		case errors.Is(err, badger.ErrKeyNotFound):
			// absent counts as zero
		case err != nil:
			return err
		default:
			raw, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}

			current, err = strconv.ParseInt(string(raw), 10, 64)
			if err != nil {
				return fmt.Errorf("%w: stored value %q", kv.ErrNotAnInteger, raw)
			}
		}

		sum := current + delta
		// Signed overflow wraps rather than trapping in Go, so detect it from
		// the sign of the operands instead of from the result alone.
		if (delta > 0 && sum < current) || (delta < 0 && sum > current) {
			return fmt.Errorf("%w: %d + %d overflows int64", kv.ErrNotAnInteger, current, delta)
		}

		next = sum

		return txn.SetEntry(entry(ns, key, strconv.AppendInt(nil, sum, 10), o))
	})
	if err != nil {
		return 0, s.translate(err, "increment", ns, key)
	}

	return next, nil
}

// Close stops the background collector, runs a final value-log collection and
// closes the database. It is idempotent.
func (s *Store) Close() error {
	var err error
	s.closeOnce.Do(func() {
		s.closed.Store(true)

		if s.gcStop != nil {
			close(s.gcStop)
			<-s.gcDone
		}

		// A last collection pass before closing, so a store that is opened and
		// closed repeatedly - every CLI invocation that owns its own store -
		// does not accumulate value-log files forever.
		s.collectGarbage(DefaultDiscardRatio)
		err = s.db.Close()
	})

	return err
}

// RunValueLogGC triggers a value-log collection immediately. Exposed on the
// concrete type for `<app> server` maintenance paths; the background collector
// covers the normal case.
func (s *Store) RunValueLogGC(discardRatio float64) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}

	if s.opts.InMemory {
		return nil
	}

	return s.db.RunValueLogGC(discardRatio)
}
