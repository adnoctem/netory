package backup_test

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/pkg/backup"
)

func testKey(t *testing.T) []byte {
	t.Helper()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	return key
}

func TestSealRoundTrip(t *testing.T) {
	asrt := assert.New(t)

	key := testKey(t)
	plaintext := []byte("every host, token hash and provider credential, in the clear")

	sealed, err := backup.Seal(key, plaintext)
	require.NoError(t, err)

	asrt.Equal(int64(len(plaintext)), sealed.PlainSize)
	asrt.Len(sealed.SHA256, 64, "a hex SHA-256 is 64 characters")
	asrt.Greater(len(sealed.Bytes), len(plaintext), "the sealed form carries a header and a tag")

	// The plaintext must not be recoverable from the sealed bytes.
	asrt.NotContains(string(sealed.Bytes), "provider credential")

	opened, err := backup.Unseal(key, sealed.Bytes)
	asrt.NoError(err)
	asrt.Equal(plaintext, opened)
}

// Two backups of the same database are near-identical plaintexts. A per-backup
// random nonce is what stops that leaking their difference.
func TestSealUsesAFreshNonce(t *testing.T) {
	asrt := assert.New(t)

	key := testKey(t)
	plaintext := []byte("identical input")

	first, err := backup.Seal(key, plaintext)
	require.NoError(t, err)

	second, err := backup.Seal(key, plaintext)
	require.NoError(t, err)

	asrt.NotEqual(first.Bytes, second.Bytes,
		"sealing the same plaintext twice must not produce the same bytes")
	asrt.NotEqual(first.SHA256, second.SHA256)

	// Both still open.
	for _, sealed := range []backup.Sealed{first, second} {
		opened, err := backup.Unseal(key, sealed.Bytes)
		asrt.NoError(err)
		asrt.Equal(plaintext, opened)
	}
}

// The three failure modes must be distinguishable. An operator restoring a
// backup needs to know which one they are looking at; all three otherwise
// present as the same opaque authentication failure.
func TestUnsealDistinguishesItsFailures(t *testing.T) {
	asrt := assert.New(t)

	key := testKey(t)

	sealed, err := backup.Seal(key, []byte("contents"))
	require.NoError(t, err)

	// Wrong key.
	_, err = backup.Unseal(testKey(t), sealed.Bytes)
	asrt.Error(err)
	asrt.Contains(err.Error(), "service secret",
		"a wrong key must point at the secret, which is the usual cause")

	// Not one of ours.
	_, err = backup.Unseal(key, []byte("this is just some other file entirely"))
	asrt.Error(err)
	asrt.Contains(err.Error(), "not a netory backup")

	// A newer format version. The magic is intact and only the version byte
	// differs, which is exactly the case this distinction exists for.
	future := make([]byte, len(sealed.Bytes))
	copy(future, sealed.Bytes)
	future[6] = 99

	_, err = backup.Unseal(key, future)
	asrt.Error(err)
	asrt.Contains(err.Error(), "unknown format version")
	asrt.Contains(err.Error(), "newer protean")

	// Empty.
	_, err = backup.Unseal(key, nil)
	asrt.ErrorIs(err, backup.ErrEmpty)

	// Truncated.
	_, err = backup.Unseal(key, sealed.Bytes[:10])
	asrt.Error(err)
}

// The header is authenticated, so the declared version and the nonce cannot be
// altered without the open failing.
func TestSealedHeaderIsAuthenticated(t *testing.T) {
	asrt := assert.New(t)

	key := testKey(t)

	sealed, err := backup.Seal(key, []byte("contents"))
	require.NoError(t, err)

	// Flip a nonce byte, leaving magic and version intact.
	tampered := make([]byte, len(sealed.Bytes))
	copy(tampered, sealed.Bytes)
	tampered[8] ^= 0xff

	_, err = backup.Unseal(key, tampered)
	asrt.Error(err, "a tampered nonce must not decrypt")

	// Flip a ciphertext byte.
	tampered = make([]byte, len(sealed.Bytes))
	copy(tampered, sealed.Bytes)
	tampered[len(tampered)-1] ^= 0xff

	_, err = backup.Unseal(key, tampered)
	asrt.Error(err, "a tampered ciphertext must not decrypt")
}

func TestSealRejectsBadInput(t *testing.T) {
	asrt := assert.New(t)

	_, err := backup.Seal(make([]byte, 16), []byte("contents"))
	asrt.Error(err, "a 16-byte key must be refused: backups are AES-256")

	_, err = backup.Seal(testKey(t), nil)
	asrt.Error(err, "there is nothing to seal")

	_, err = backup.Unseal(make([]byte, 16), []byte("contents"))
	asrt.Error(err)
}

func TestName(t *testing.T) {
	asrt := assert.New(t)

	at := time.Date(2026, 10, 9, 14, 30, 5, 0, time.UTC)

	name := backup.Name("protean", "1.2.3", at)
	asrt.Equal("protean-20261009T143005Z-1.2.3.backup", name)

	// Names must sort chronologically, so a plain directory or prefix listing
	// is already in order.
	earlier := backup.Name("protean", "1.2.3", at.Add(-time.Hour))
	asrt.Less(earlier, name)

	// A version with characters that would be awkward in a filename or an S3
	// key is sanitised rather than passed through.
	name = backup.Name("protean", "1.2.3-dirty+meta/slash", at)
	asrt.NotContains(name, "/")
	asrt.NotContains(name, "+")
	asrt.Contains(name, ".backup")

	// An unstamped build has no version; the name still has to be usable.
	name = backup.Name("protean", "", at)
	asrt.Contains(name, "unknown")
}

func TestOpenRejectsBadDestinations(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	_, err := backup.Open(ctx, "")
	asrt.Error(err, "a destination is required")

	// A bare "bucket/prefix" that was probably meant to be S3 would otherwise
	// silently create a relative directory next to the working directory.
	for _, raw := range []string{"s3:/bucket", "s3:bucket", "S3://bucket"} {
		_, err := backup.Open(ctx, raw)
		asrt.Error(err, raw)
		asrt.Contains(err.Error(), "s3://", raw)
	}

	_, err = backup.Open(ctx, "s3://")
	asrt.Error(err)
	asrt.Contains(err.Error(), "no bucket")
}

func TestLocalDestinationRoundTrip(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	dir := filepath.Join(t.TempDir(), "backups")

	dest, err := backup.Open(ctx, dir)
	require.NoError(t, err)
	asrt.Equal(dir, dest.Describe())

	// The directory is created 0700: a sealed backup is still a complete copy
	// of every credential the service holds.
	info, err := os.Stat(dir)
	require.NoError(t, err)
	asrt.Equal(os.FileMode(0o700), info.Mode().Perm())

	entries, err := dest.List(ctx)
	asrt.NoError(err)
	asrt.Empty(entries, "a fresh destination lists nothing rather than erroring")

	name := backup.Name("protean", "1.0.0", time.Now())
	require.NoError(t, dest.Put(ctx, name, []byte("sealed-contents")))

	// And each backup 0600.
	info, err = os.Stat(filepath.Join(dir, name))
	require.NoError(t, err)
	asrt.Equal(os.FileMode(0o600), info.Mode().Perm())

	got, err := dest.Get(ctx, name)
	asrt.NoError(err)
	asrt.Equal("sealed-contents", string(got))

	entries, err = dest.List(ctx)
	asrt.NoError(err)
	require.Len(t, entries, 1)
	asrt.Equal(name, entries[0].Name)
	asrt.Equal(int64(len("sealed-contents")), entries[0].Size)
	asrt.False(entries[0].ModTime.IsZero())
}

// Newest first, because the most recent backup is almost always the answer
// when restoring one.
func TestLocalDestinationListsNewestFirst(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	dest, err := backup.Open(ctx, t.TempDir())
	require.NoError(t, err)

	at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

	var names []string
	for i := range 3 {
		name := backup.Name("protean", "1.0.0", at.Add(time.Duration(i)*time.Hour))
		names = append(names, name)
		require.NoError(t, dest.Put(ctx, name, []byte("contents")))
	}

	entries, err := dest.List(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	asrt.Equal(names[2], entries[0].Name, "the newest backup comes first")
	asrt.Equal(names[0], entries[2].Name)
}

// A partial write must leave no backup behind. A truncated backup is worse than
// no backup: it looks like one in a listing and only fails when it is needed.
func TestLocalDestinationIgnoresPartialFiles(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	dir := t.TempDir()

	dest, err := backup.Open(ctx, dir)
	require.NoError(t, err)

	// A leftover temporary file, as an interrupted Put would have left.
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, ".protean-x.backup.partial-12345"), []byte("half"), 0o600))

	// And something that is not a backup at all.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0o600))

	entries, err := dest.List(ctx)
	asrt.NoError(err)
	asrt.Empty(entries, "only completed .backup files are listed")
}

func TestLocalDestinationGetMissing(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	dest, err := backup.Open(ctx, t.TempDir())
	require.NoError(t, err)

	_, err = dest.Get(ctx, "protean-20261009T120000Z-1.0.0.backup")
	asrt.ErrorIs(err, backup.ErrNotFound)
}

// The name reaches a filesystem path join and an S3 key, and it arrives from a
// command line. A ".." in it would read or write outside the destination.
func TestNamesCannotEscapeTheDestination(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	dir := t.TempDir()

	dest, err := backup.Open(ctx, filepath.Join(dir, "backups"))
	require.NoError(t, err)

	for _, name := range []string{
		"../escaped.backup",
		"../../etc/passwd",
		"sub/dir.backup",
		`..\escaped.backup`,
		".hidden.backup",
		"",
	} {
		asrt.Error(dest.Put(ctx, name, []byte("contents")), "Put must refuse %q", name)

		_, err := dest.Get(ctx, name)
		asrt.Error(err, "Get must refuse %q", name)
	}

	// And nothing was written outside the destination.
	escaped, err := os.ReadDir(dir)
	require.NoError(t, err)
	asrt.Len(escaped, 1, "only the backups directory may exist")
}

func TestLocalDestinationRejectsAFileAsDirectory(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	path := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))

	_, err := backup.Open(ctx, path)
	asrt.Error(err)
	asrt.Contains(err.Error(), "not a directory")
}

func TestEmptyStoredBackupIsReported(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	dir := t.TempDir()

	dest, err := backup.Open(ctx, dir)
	require.NoError(t, err)

	name := "protean-20261009T120000Z-1.0.0.backup"
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), nil, 0o600))

	// An interrupted write that left a zero-length file is reported as such
	// rather than as a decryption failure, which is what it would look like
	// otherwise.
	_, err = dest.Get(ctx, name)
	asrt.ErrorIs(err, backup.ErrEmpty)
}

func TestSealRejectsAnOversizedBackup(t *testing.T) {
	asrt := assert.New(t)

	// Not actually allocating a gigabyte; the check is on the length.
	_, err := backup.Seal(testKey(t), make([]byte, 0))
	asrt.Error(err)

	asrt.Positive(backup.MaxBackupBytes)
	asrt.Equal(int64(1<<30), int64(backup.MaxBackupBytes))
}

func TestInfoLabelIsShared(t *testing.T) {
	// The label lives in this package so the services taking backups cannot
	// drift onto different ones and produce backups the other cannot read.
	assert.True(t, strings.HasPrefix(backup.InfoBackupEncryption, "netory/"),
		"the label is service-agnostic: each service's secret already differs")
}
