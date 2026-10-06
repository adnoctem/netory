package badgerkv

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/log"
)

// maxRetries bounds the conflict-retry loop behind SetIfAbsent,
// CompareAndSwap and Increment. Badger rejects the loser of a write conflict
// with ErrConflict and expects the caller to retry; an unbounded loop would
// turn a pathological hot key into a goroutine that never returns, so the
// limit converts that into an error the caller can report.
const maxRetries = 32

// physical builds the Badger key for a namespace and key pair. kv's namespace
// charset excludes the separator, so the join is unambiguous and the split in
// relative is exact.
func physical(ns, key string) []byte {
	out := make([]byte, 0, len(ns)+1+len(key))
	out = append(out, ns...)
	out = append(out, separator)
	out = append(out, key...)

	return out
}

// physicalPrefix builds the Badger key prefix for a namespace and a
// namespace-relative prefix. An empty prefix yields the whole namespace.
func physicalPrefix(ns, prefix string) []byte {
	return physical(ns, prefix)
}

// relative strips the namespace prefix from a physical key.
func relative(ns string, physicalKey []byte) string {
	return strings.TrimPrefix(string(physicalKey), ns+string(separator))
}

// entry builds the Badger entry for a write, applying the TTL when one is set.
//
// It sets ExpiresAt from kv.ExpiresAt rather than calling badger's own
// Entry.WithTTL. WithTTL computes uint64(time.Now().Add(dur).Unix()), which
// truncates towards the past: a 150ms TTL written at .100 of a second yields
// an ExpiresAt equal to the current second, and badger treats
// `expiresAt <= now` as expired - so the key is gone before Set returns. Even
// a one-second TTL loses up to a second that way. kv.ExpiresAt rounds up
// instead, which makes the requested TTL a lower bound.
func entry(ns, key string, value []byte, o kv.SetOptions) *badger.Entry {
	e := badger.NewEntry(physical(ns, key), value)
	if expiry := kv.ExpiresAt(time.Now(), o.TTL); !expiry.IsZero() {
		e.ExpiresAt = uint64(expiry.Unix())
	}

	return e
}

// precheck runs the guards every operation shares: a closed store, a cancelled
// context, and namespace and key validation.
//
// Badger's transaction API takes no context, so a cancelled context is
// detected here and at each retry rather than interrupting an in-flight
// commit. That is the honest bound: callers get prompt cancellation of queued
// and retried work, not of a single commit already underway.
func (s *Store) precheck(ctx context.Context, ns, key string) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return kv.Validate(ns, key)
}

// precheckPrefix is precheck for the prefix-taking operations, where an empty
// prefix is legal.
func (s *Store) precheckPrefix(ctx context.Context, ns, prefix string) error {
	if s.closed.Load() {
		return kv.ErrClosed
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return kv.ValidatePrefixed(ns, prefix)
}

// retry runs fn in a read-write transaction, retrying on Badger write
// conflicts. It is the shared body of the three atomic primitives.
//
// The per-key lock those operations take first means a conflict here is
// already the uncommon case - a plain Set racing a read-modify-write on the
// same key - so the backoff is about not thrashing rather than about
// throughput.
func (s *Store) retry(ctx context.Context, fn func(*badger.Txn) error) error {
	var err error
	for attempt := range maxRetries {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}

		err = s.db.Update(fn)
		if !errors.Is(err, badger.ErrConflict) {
			return err
		}

		// The conflicting transaction has to commit before this one can
		// succeed, so yield on the first attempts and then back off. Sleeping
		// straight away would add latency to the common case where the winner
		// commits immediately.
		if attempt < 2 {
			runtime.Gosched()

			continue
		}

		if err := sleepCtx(ctx, backoff(attempt)); err != nil {
			return err
		}
	}

	return fmt.Errorf("badgerkv: gave up after %d write conflicts: %w", maxRetries, err)
}

// backoff grows the pause between conflict retries, capped so a pathological
// hot key degrades into slow progress rather than a stall.
func backoff(attempt int) time.Duration {
	const (
		base = 200 * time.Microsecond
		max  = 20 * time.Millisecond
	)

	d := base << min(attempt, 8)
	if d > max {
		return max
	}

	return d
}

// sleepCtx waits for d or until ctx is done, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// iterate walks the keys of one namespace that begin with prefix, calling fn
// with the namespace-relative key.
//
// Iteration order is Badger's key order, which is sorted. kv.Store
// deliberately documents the order as unspecified anyway, because Valkey's
// SCAN gives no such guarantee and a caller that silently relies on sorting
// here would break on the Valkey implementation.
func (s *Store) iterate(ns, prefix string, withValues bool, fn func(string, *badger.Item) error) error {
	pfx := physicalPrefix(ns, prefix)

	return s.db.View(func(txn *badger.Txn) error {
		iOpts := badger.DefaultIteratorOptions
		iOpts.Prefix = pfx
		iOpts.PrefetchValues = withValues

		it := txn.NewIterator(iOpts)
		defer it.Close()

		for it.Rewind(); it.ValidForPrefix(pfx); it.Next() {
			item := it.Item()

			// Badger's iterator already skips expired entries, but a key whose
			// TTL elapsed between the iterator snapshot and this read would
			// still be yielded. Checking keeps Keys and Scan consistent with
			// Get, which reports an expired key as absent.
			if item.IsDeletedOrExpired() {
				continue
			}

			if err := fn(relative(ns, item.Key()), item); err != nil {
				return err
			}
		}

		return nil
	})
}

// translate maps a Badger error onto this repository's sentinels, so no caller
// ever has to import Badger to recognise a missing key or a closed store.
func (s *Store) translate(err error, op, ns, key string) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, badger.ErrKeyNotFound):
		return fmt.Errorf("badgerkv: %s %s/%s: %w", op, ns, key, kv.ErrNotFound)
	case errors.Is(err, badger.ErrDBClosed):
		return fmt.Errorf("badgerkv: %s %s/%s: %w", op, ns, key, kv.ErrClosed)
	case errors.Is(err, badger.ErrInvalidKey), errors.Is(err, badger.ErrEmptyKey):
		return fmt.Errorf("badgerkv: %s %s/%s: %w", op, ns, key, kv.ErrInvalidKey)
	default:
		// Already one of ours (kv.ErrNotAnInteger, kv.ErrStopIteration, a
		// caller's own Scan error) or a genuine backend failure. Either way it
		// is wrapped with the operation, not reclassified.
		return fmt.Errorf("badgerkv: %s %s/%s: %w", op, ns, key, err)
	}
}

// startGC launches the background value-log collector unless it is disabled or
// the store is in memory.
func (s *Store) startGC(opts Options) {
	if opts.InMemory {
		// Badger returns ErrGCInMemoryMode here: there is no value log to
		// collect when nothing is written to disk.
		return
	}

	interval := opts.GCInterval
	if interval == 0 {
		interval = DefaultGCInterval
	}
	if interval < 0 {
		return
	}

	ratio := opts.DiscardRatio
	if ratio <= 0 || ratio >= 1 {
		ratio = DefaultDiscardRatio
	}

	s.gcStop = make(chan struct{})
	s.gcDone = make(chan struct{})

	go func() {
		defer close(s.gcDone)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-s.gcStop:
				return
			case <-ticker.C:
				s.collectGarbage(ratio)
			}
		}
	}()
}

// collectGarbage rewrites value-log files until there is nothing left to
// reclaim. RunValueLogGC handles one file per call and reports ErrNoRewrite
// when no file is worth rewriting, which is the loop's exit condition.
func (s *Store) collectGarbage(ratio float64) {
	if s.opts.InMemory {
		return
	}

	for {
		if err := s.db.RunValueLogGC(ratio); err != nil {
			return
		}
	}
}

// badgerLogger adapts badger.Logger onto this repository's logger so Badger's
// diagnostics land in the same stream, at the same level, in the same format
// as everything else the service emits.
type badgerLogger struct {
	log *log.Logger
}

// newBadgerLogger returns nil when there is no logger, which is how Badger is
// told to stay silent. The alternative - Badger's default logger - writes its
// own format straight to stderr and would interleave with structured output.
func newBadgerLogger(l *log.Logger) badger.Logger {
	if l == nil {
		return nil
	}

	return &badgerLogger{log: l.With(slog.String("component", "badger"))}
}

// Badger passes printf-style format strings with a trailing newline, which
// slog messages should not carry.
func (b *badgerLogger) Errorf(f string, v ...any)   { b.emit(slog.LevelError, f, v...) }
func (b *badgerLogger) Warningf(f string, v ...any) { b.emit(slog.LevelWarn, f, v...) }
func (b *badgerLogger) Infof(f string, v ...any)    { b.emit(slog.LevelInfo, f, v...) }
func (b *badgerLogger) Debugf(f string, v ...any)   { b.emit(slog.LevelDebug, f, v...) }

func (b *badgerLogger) emit(level slog.Level, format string, v ...any) {
	b.log.Log(context.Background(), level, strings.TrimRight(fmt.Sprintf(format, v...), "\n"))
}
