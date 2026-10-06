package app

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/adnoctem/netory/pkg/backup"
	"github.com/adnoctem/netory/pkg/secret"
)

// BackupResult describes a backup that was just taken.
type BackupResult struct {
	// Name is the stored name, which is what Restore takes.
	Name string `json:"name"`

	// Destination is where it went, with nothing secret in it.
	Destination string `json:"destination"`

	// PlainSize and StoredSize are the sizes before and after sealing.
	PlainSize  int64 `json:"plain_size"`
	StoredSize int64 `json:"stored_size"`

	// SHA256 is the digest of the stored bytes, so an operator can compare
	// what was written against what the destination reports.
	SHA256 string `json:"sha256"`

	// Version is the Badger transaction version the snapshot was taken at.
	Version uint64 `json:"version"`

	// TakenAt is when it was taken.
	TakenAt time.Time `json:"taken_at"`
}

// BackupKey derives the key backups are sealed under.
//
// A separate label from the database's own encryption key, so the two are
// cryptographically independent: a backup key recovered from somewhere does
// not open the live database, and vice versa.
func BackupKey(sec *secret.Secret) ([]byte, error) {
	return sec.DeriveEncryptionKey(backup.InfoBackupEncryption)
}

// Backup takes a backup of the live database and stores it sealed.
//
// Badger streams at a transaction timestamp, so this is a consistent snapshot
// taken without stopping the server or blocking writers - which is what makes
// a scheduled backup of a running service possible.
//
// The snapshot is sealed before it goes anywhere. Badger's own backup stream is
// plaintext even for an encrypted database (pkg/kv/badgerkv has a test proving
// it), so writing it unsealed to a filesystem or a bucket would undo the
// database encryption silently.
func (s *State) Backup(ctx context.Context, destination string) (BackupResult, error) {
	dest, err := backup.Open(ctx, destination)
	if err != nil {
		return BackupResult{}, err
	}

	key, err := BackupKey(s.Secret)
	if err != nil {
		return BackupResult{}, err
	}

	var plain bytes.Buffer

	version, err := s.Store.Backup(&plain)
	if err != nil {
		return BackupResult{}, err
	}

	sealed, err := backup.Seal(key, plain.Bytes())
	if err != nil {
		return BackupResult{}, err
	}

	// The plaintext snapshot is dropped as soon as it is sealed. It holds every
	// credential in the database, so there is no reason to keep it reachable
	// for the length of an upload.
	plain.Reset()

	takenAt := time.Now().UTC()
	name := backup.Name(Name, s.Stamp.Version, takenAt)

	if err := dest.Put(ctx, name, sealed.Bytes); err != nil {
		return BackupResult{}, err
	}

	s.Log.Info("backup written",
		"name", name,
		"destination", dest.Describe(),
		"plain_size", sealed.PlainSize,
		"stored_size", len(sealed.Bytes),
		"sha256", sealed.SHA256,
	)

	return BackupResult{
		Name:        name,
		Destination: dest.Describe(),
		PlainSize:   sealed.PlainSize,
		StoredSize:  int64(len(sealed.Bytes)),
		SHA256:      sealed.SHA256,
		Version:     version,
		TakenAt:     takenAt,
	}, nil
}

// ListBackups returns the backups stored at a destination, newest first.
func (s *State) ListBackups(ctx context.Context, destination string) ([]backup.Entry, string, error) {
	dest, err := backup.Open(ctx, destination)
	if err != nil {
		return nil, "", err
	}

	entries, err := dest.List(ctx)
	if err != nil {
		return nil, dest.Describe(), err
	}

	return entries, dest.Describe(), nil
}

// VerifyBackup downloads a stored backup and confirms it decrypts under this
// service's secret, without restoring it.
//
// Worth having separately from restore: a backup nobody has ever opened is a
// backup nobody knows works, and finding out during an incident is the wrong
// time. Verifying needs no stopped server and changes nothing.
func (s *State) VerifyBackup(ctx context.Context, destination, name string) (int64, error) {
	dest, err := backup.Open(ctx, destination)
	if err != nil {
		return 0, err
	}

	key, err := BackupKey(s.Secret)
	if err != nil {
		return 0, err
	}

	sealed, err := dest.Get(ctx, name)
	if err != nil {
		return 0, err
	}

	plain, err := backup.Unseal(key, sealed)
	if err != nil {
		return 0, fmt.Errorf("backup %s at %s: %w", name, dest.Describe(), err)
	}

	return int64(len(plain)), nil
}
