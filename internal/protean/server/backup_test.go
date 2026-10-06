package server_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/protean/app"
	"github.com/adnoctem/netory/pkg/backup"
)

// A backup of the live database must be sealed before it goes anywhere.
// Badger's own backup stream is plaintext even for an encrypted database, so
// this is the assertion that the sealing actually happens on the real path.
func TestBackupIsSealedOnDisk(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, nil)

	dir := filepath.Join(t.TempDir(), "backups")

	result, err := h.state.Backup(ctx, dir)
	require.NoError(t, err)

	asrt.Contains(result.Name, "protean-")
	asrt.True(strings.HasSuffix(result.Name, ".backup"))
	asrt.Positive(result.PlainSize)
	asrt.Positive(result.StoredSize)
	asrt.Len(result.SHA256, 64)
	asrt.Equal(dir, result.Destination)

	dest, err := backup.Open(ctx, dir)
	require.NoError(t, err)

	stored, err := dest.Get(ctx, result.Name)
	require.NoError(t, err)

	// The harness configures dyn.example.org, so the hostname is in the
	// database and would be in a plaintext backup.
	asrt.NotContains(string(stored), h.host,
		"the stored backup must be sealed - a plaintext one would leak every credential")

	// It does decrypt under the service's own key.
	key, err := app.BackupKey(h.state.Secret)
	require.NoError(t, err)

	plain, err := backup.Unseal(key, stored)
	asrt.NoError(err)
	asrt.Contains(string(plain), h.host, "and the plaintext does hold the data")
}

func TestBackupListAndVerify(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, nil)

	dir := filepath.Join(t.TempDir(), "backups")

	entries, described, err := h.state.ListBackups(ctx, dir)
	asrt.NoError(err)
	asrt.Empty(entries)
	asrt.Equal(dir, described)

	result, err := h.state.Backup(ctx, dir)
	require.NoError(t, err)

	entries, _, err = h.state.ListBackups(ctx, dir)
	asrt.NoError(err)
	require.Len(t, entries, 1)
	asrt.Equal(result.Name, entries[0].Name)

	size, err := h.state.VerifyBackup(ctx, dir, result.Name)
	asrt.NoError(err)
	asrt.Equal(result.PlainSize, size)

	_, err = h.state.VerifyBackup(ctx, dir, "protean-20261009T120000Z-1.0.0.backup")
	asrt.ErrorIs(err, backup.ErrNotFound)
}

// A backup taken from one service's secret must not open under another's. This
// is the property that makes "lose the secret, lose the backup" true, and it is
// worth asserting rather than assuming.
func TestBackupDoesNotOpenUnderAnotherSecret(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()

	first := newHarness(t, nil)
	second := newHarness(t, nil)

	dir := filepath.Join(t.TempDir(), "backups")

	result, err := first.state.Backup(ctx, dir)
	require.NoError(t, err)

	// The second harness has its own generated secret.
	_, err = second.state.VerifyBackup(ctx, dir, result.Name)
	asrt.Error(err)
	asrt.Contains(err.Error(), "service secret")
}

// The backup key must be independent of the database's own encryption key, so
// one recovered from somewhere does not open the other.
func TestBackupKeyIsIndependentOfTheDatabaseKey(t *testing.T) {
	asrt := assert.New(t)
	h := newHarness(t, nil)

	backupKey, err := app.BackupKey(h.state.Secret)
	require.NoError(t, err)

	databaseKey, err := h.state.Secret.DeriveEncryptionKey(app.InfoKVEncryption)
	require.NoError(t, err)

	asrt.Len(backupKey, 32)
	asrt.NotEqual(databaseKey, backupKey,
		"the two keys must be cryptographically independent")
}

func TestBackupRejectsABadDestination(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, nil)

	_, err := h.state.Backup(ctx, "")
	asrt.Error(err)

	// A bare bucket-looking path would otherwise silently create a relative
	// directory instead of reaching S3.
	_, err = h.state.Backup(ctx, "s3:/typo-bucket")
	asrt.Error(err)
	asrt.Contains(err.Error(), "s3://")
}

// Backups are taken from the live database without stopping it, and the data
// written just before the backup has to be in it.
func TestBackupCapturesRecentWrites(t *testing.T) {
	asrt := assert.New(t)
	ctx := context.Background()
	h := newHarness(t, nil)

	require.NoError(t, h.state.Hosts.Add(ctx, app.Host{
		Name: "late.example.org", Provider: "fake-main", ManageA: true,
	}))

	dir := filepath.Join(t.TempDir(), "backups")

	result, err := h.state.Backup(ctx, dir)
	require.NoError(t, err)

	dest, err := backup.Open(ctx, dir)
	require.NoError(t, err)

	stored, err := dest.Get(ctx, result.Name)
	require.NoError(t, err)

	key, err := app.BackupKey(h.state.Secret)
	require.NoError(t, err)

	plain, err := backup.Unseal(key, stored)
	require.NoError(t, err)

	asrt.Contains(string(plain), "late.example.org",
		"a write made before the backup must be in it")
}
