package badgerkv_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
)

// THE load-bearing test for pkg/backup's existence.
//
// Badger reads key-value pairs through the normal transaction path, which
// decrypts them, so a backup of an *encrypted* database is a plaintext stream.
// Writing one straight to a file or a bucket would undo the database encryption
// silently. This asserts the hazard is real, so nobody later decides the
// sealing in pkg/backup is redundant.
func TestBackupOfAnEncryptedDatabaseIsPlaintext(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	dir := filepath.Join(t.TempDir(), "store")

	store, err := badgerkv.New(badgerkv.Options{
		Path:          dir,
		EncryptionKey: key,
		Logger:        silent(t),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	const canary = "SMTP-PASSWORD-CANARY-VALUE"
	require.NoError(t, store.Set(ctx, "secrets", "smtp-password", []byte(canary)))

	var buf bytes.Buffer
	version, err := store.Backup(&buf)
	require.NoError(t, err)

	asrt.Positive(version, "the backup reports the transaction version it snapshotted at")
	asrt.Contains(buf.String(), canary,
		"a backup of an encrypted database is plaintext - this is why pkg/backup seals it")
}

func TestBackupAndRestoreRoundTrip(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	source, err := badgerkv.New(badgerkv.Options{InMemory: true, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = source.Close() })

	want := map[string]string{
		"host/a.example":    "first",
		"host/b.example":    "second",
		"outbox/pending/01": "event",
	}
	for key, value := range want {
		require.NoError(t, source.Set(ctx, "data", key, []byte(value)))
	}

	var buf bytes.Buffer
	_, err = source.Backup(&buf)
	require.NoError(t, err)

	target, err := badgerkv.New(badgerkv.Options{InMemory: true, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = target.Close() })

	empty, err := target.IsEmpty()
	require.NoError(t, err)
	asrt.True(empty, "a fresh database must report itself empty")

	require.NoError(t, target.Restore(bytes.NewReader(buf.Bytes())))

	for key, value := range want {
		got, err := target.Get(ctx, "data", key)
		asrt.NoError(err, key)
		asrt.Equal(value, string(got), key)
	}

	empty, err = target.IsEmpty()
	asrt.NoError(err)
	asrt.False(empty, "a restored database is not empty")
}

// A backup can be restored into a database encrypted under a *different* key:
// the stream is plaintext, so the two encryptions are independent. Worth
// pinning, because it is what makes "restore onto a new host" work and it is
// not obvious.
func TestRestoreIntoADifferentlyEncryptedDatabase(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	firstKey := make([]byte, 32)
	_, err := rand.Read(firstKey)
	require.NoError(t, err)

	secondKey := make([]byte, 32)
	_, err = rand.Read(secondKey)
	require.NoError(t, err)

	source, err := badgerkv.New(badgerkv.Options{
		Path:          filepath.Join(t.TempDir(), "source"),
		EncryptionKey: firstKey,
		Logger:        silent(t),
	})
	require.NoError(t, err)
	require.NoError(t, source.Set(ctx, "data", "key", []byte("value")))

	var buf bytes.Buffer
	_, err = source.Backup(&buf)
	require.NoError(t, err)
	require.NoError(t, source.Close())

	target, err := badgerkv.New(badgerkv.Options{
		Path:          filepath.Join(t.TempDir(), "target"),
		EncryptionKey: secondKey,
		Logger:        silent(t),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = target.Close() })

	require.NoError(t, target.Restore(bytes.NewReader(buf.Bytes())))

	got, err := target.Get(ctx, "data", "key")
	asrt.NoError(err)
	asrt.Equal("value", string(got))
}

// Badger's Load merges rather than replaces, which is almost never what a
// restore means. Pinned here so the CLI's refusal to restore into a non-empty
// database has a documented reason.
func TestRestoreMergesRatherThanReplaces(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	source, err := badgerkv.New(badgerkv.Options{InMemory: true, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = source.Close() })

	require.NoError(t, source.Set(ctx, "data", "shared", []byte("from-backup")))

	var buf bytes.Buffer
	_, err = source.Backup(&buf)
	require.NoError(t, err)

	target, err := badgerkv.New(badgerkv.Options{InMemory: true, Logger: silent(t)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = target.Close() })

	require.NoError(t, target.Set(ctx, "data", "shared", []byte("pre-existing")))
	require.NoError(t, target.Set(ctx, "data", "only-here", []byte("survivor")))

	require.NoError(t, target.Restore(bytes.NewReader(buf.Bytes())))

	shared, err := target.Get(ctx, "data", "shared")
	asrt.NoError(err)
	asrt.Equal("from-backup", string(shared), "a key in the backup overwrites its counterpart")

	// And the key absent from the backup is still there, which is the merge
	// hazard: the result is neither the backup nor what was there before.
	survivor, err := target.Get(ctx, "data", "only-here")
	asrt.NoError(err)
	asrt.Equal("survivor", string(survivor),
		"a key absent from the backup survives - this is why restore refuses a non-empty database")
}

func TestBackupOnAClosedStore(t *testing.T) {
	asrt := assert.New(t)

	store, err := badgerkv.New(badgerkv.Options{InMemory: true, Logger: silent(t)})
	require.NoError(t, err)
	require.NoError(t, store.Close())

	var buf bytes.Buffer
	_, err = store.Backup(&buf)
	asrt.ErrorIs(err, kv.ErrClosed)

	asrt.ErrorIs(store.Restore(bytes.NewReader(nil)), kv.ErrClosed)

	_, err = store.IsEmpty()
	asrt.ErrorIs(err, kv.ErrClosed)
}
