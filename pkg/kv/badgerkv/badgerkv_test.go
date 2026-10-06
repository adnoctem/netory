package badgerkv_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
	"github.com/adnoctem/netory/pkg/kv/kvtest"
	"github.com/adnoctem/netory/pkg/log"
)

// silent keeps Badger's own startup chatter out of the test log while still
// exercising the logger adapter rather than the nil path.
func silent(t *testing.T) *log.Logger {
	t.Helper()

	return log.New(log.WithOutput(&strings.Builder{}), log.WithLevel(slog.LevelError))
}

// The conformance suite runs twice, because an in-memory Badger takes a
// different code path to an on-disk one - no value log, no GC, no directory -
// and tests throughout this repository will use the in-memory variant in place
// of a mock. Both have to behave identically or the tests stop being evidence
// about the real store.
func TestConformanceOnDisk(t *testing.T) {
	kvtest.Suite(t, func(t *testing.T) kv.Store {
		t.Helper()

		store, err := badgerkv.New(badgerkv.Options{
			Path:   filepath.Join(t.TempDir(), "store"),
			Logger: silent(t),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = store.Close() })

		return store
	})
}

func TestConformanceInMemory(t *testing.T) {
	kvtest.Suite(t, func(t *testing.T) kv.Store {
		t.Helper()

		store, err := badgerkv.New(badgerkv.Options{InMemory: true, Logger: silent(t)})
		require.NoError(t, err)
		t.Cleanup(func() { _ = store.Close() })

		return store
	})
}

// Encryption at rest is what makes the Badger directory safe to hold provider
// credentials and notifier passwords, so the suite runs against an encrypted
// store too - the derived key must not change any observable semantics.
func TestConformanceEncrypted(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	kvtest.Suite(t, func(t *testing.T) kv.Store {
		t.Helper()

		store, err := badgerkv.New(badgerkv.Options{
			Path:          filepath.Join(t.TempDir(), "store"),
			EncryptionKey: key,
			Logger:        silent(t),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = store.Close() })

		return store
	})
}

func TestNewRejectsBadOptions(t *testing.T) {
	asrt := assert.New(t)

	_, err := badgerkv.New(badgerkv.Options{})
	asrt.Error(err, "the zero Options must be rejected rather than defaulting to some path")

	_, err = badgerkv.New(badgerkv.Options{InMemory: true, Path: t.TempDir()})
	asrt.Error(err, "Path and InMemory are mutually exclusive")
}

// Badger accepts only 16, 24 or 32-byte keys. The error has to name the
// derivation path, because the mistake this catches is passing the raw service
// secret where a derived key belongs.
func TestNewRejectsWrongSizedEncryptionKey(t *testing.T) {
	asrt := assert.New(t)

	for _, size := range []int{1, 15, 17, 31, 33, 64} {
		_, err := badgerkv.New(badgerkv.Options{
			Path:          filepath.Join(t.TempDir(), "store"),
			EncryptionKey: make([]byte, size),
			Logger:        silent(t),
		})
		if asrt.Error(err, "%d-byte key", size) {
			asrt.Contains(err.Error(), "pkg/secret", "%d-byte key", size)
		}
	}
}

// Data written under an encryption key must not be readable without it. This
// is the assertion behind "all state lives in an encrypted Badger database".
func TestEncryptedDataIsNotReadableWithoutTheKey(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "store")

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	store, err := badgerkv.New(badgerkv.Options{Path: dir, EncryptionKey: key, Logger: silent(t)})
	require.NoError(t, err)
	require.NoError(t, store.Set(ctx, "secrets", "smtp-password", []byte("super-secret-value")))
	require.NoError(t, store.Close())

	_, err = badgerkv.New(badgerkv.Options{Path: dir, Logger: silent(t)})
	asrt.Error(err, "an encrypted database must not open without its key")

	wrong := make([]byte, 32)
	_, err = rand.Read(wrong)
	require.NoError(t, err)

	_, err = badgerkv.New(badgerkv.Options{Path: dir, EncryptionKey: wrong, Logger: silent(t)})
	asrt.Error(err, "an encrypted database must not open under a different key")

	reopened, err := badgerkv.New(badgerkv.Options{Path: dir, EncryptionKey: key, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	got, err := reopened.Get(ctx, "secrets", "smtp-password")
	asrt.NoError(err)
	asrt.Equal("super-secret-value", string(got))
}

// Badger's exclusive directory lock is what makes "one binary, one database
// owner" an enforced constraint rather than a documented convention, so the
// services can rely on the CLI being unable to open the server's store.
func TestDirectoryLockIsExclusive(t *testing.T) {
	asrt := assert.New(t)
	dir := filepath.Join(t.TempDir(), "store")

	first, err := badgerkv.New(badgerkv.Options{Path: dir, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })

	_, err = badgerkv.New(badgerkv.Options{Path: dir, Logger: silent(t)})
	asrt.Error(err, "a second store must not open a directory another already owns")
}

// Values survive a close and reopen. An on-disk store that silently lost data
// across a restart would break "nothing lost on restart" for the outbox.
func TestPersistenceAcrossReopen(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "store")

	store, err := badgerkv.New(badgerkv.Options{Path: dir, Logger: silent(t)})
	require.NoError(t, err)
	require.NoError(t, store.Set(ctx, "outbox", "event/1", []byte("pending")))
	require.NoError(t, store.Close())

	reopened, err := badgerkv.New(badgerkv.Options{Path: dir, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })

	got, err := reopened.Get(ctx, "outbox", "event/1")
	asrt.NoError(err)
	asrt.Equal("pending", string(got))
}

func TestPathAndOptions(t *testing.T) {
	asrt := assert.New(t)
	dir := filepath.Join(t.TempDir(), "store")

	store, err := badgerkv.New(badgerkv.Options{Path: dir, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	asrt.Equal(dir, store.Path())
	asrt.Equal(dir, store.Options().Dir)

	mem, err := badgerkv.New(badgerkv.Options{InMemory: true, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = mem.Close() })

	asrt.Empty(mem.Path())
	asrt.True(mem.Options().InMemory)
}

// Badger has no value log in memory and reports ErrGCInMemoryMode if asked to
// collect one, so the collector has to be a no-op there rather than an error
// surfacing from a background goroutine nobody reads.
func TestRunValueLogGC(t *testing.T) {
	asrt := assert.New(t)

	mem, err := badgerkv.New(badgerkv.Options{InMemory: true, Logger: silent(t)})
	require.NoError(t, err)
	asrt.NoError(mem.RunValueLogGC(0.5), "value-log GC must be a no-op in memory")
	require.NoError(t, mem.Close())

	asrt.ErrorIs(mem.RunValueLogGC(0.5), kv.ErrClosed)
}

// A cancelled context must stop work before it reaches the database, since
// Badger's transaction API takes no context of its own.
func TestCancelledContext(t *testing.T) {
	asrt := assert.New(t)

	store, err := badgerkv.New(badgerkv.Options{InMemory: true, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = store.Get(ctx, "alpha", "key")
	asrt.ErrorIs(err, context.Canceled)

	asrt.ErrorIs(store.Set(ctx, "alpha", "key", []byte("v")), context.Canceled)

	_, err = store.Increment(ctx, "alpha", "counter", 1)
	asrt.ErrorIs(err, context.Canceled)
}

// Scan documents its Entry as valid only for the duration of the callback,
// which is what lets the implementation avoid a copy per entry. A caller that
// retains the slice gets undefined contents, so this asserts the documented
// way of keeping a value works.
func TestScanValueMustBeCopiedToBeRetained(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	store, err := badgerkv.New(badgerkv.Options{InMemory: true, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	for _, k := range []string{"a", "b", "c"} {
		require.NoError(t, store.Set(ctx, "alpha", k, []byte("value-"+k)))
	}

	got := map[string]string{}
	asrt.NoError(store.Scan(ctx, "alpha", "", func(e kv.Entry) error {
		got[e.Key] = string(bytes.Clone(e.Value))

		return nil
	}))
	asrt.Equal(map[string]string{"a": "value-a", "b": "value-b", "c": "value-c"}, got)
}
