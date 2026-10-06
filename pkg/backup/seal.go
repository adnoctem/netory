package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// InfoBackupEncryption is the HKDF label callers should derive the sealing key
// under. It lives here so the two services that take backups cannot drift onto
// different labels and produce backups the other cannot read.
const InfoBackupEncryption = "netory/backup-encryption"

// The sealed format. A header rather than a bare ciphertext, so a file found on
// disk years later identifies itself and a format change is detectable instead
// of being read as corruption.
var magic = [6]byte{'N', 'T', 'R', 'Y', 'B', 'K'}

// formatVersion is the sealed-format version.
//
// Checked on open, so a backup written by a future version fails with "unknown
// format version" rather than a decryption error that looks like a wrong key -
// which is the single most alarming and least informative thing a restore
// could say.
const formatVersion uint8 = 1

// headerLen is magic + version + nonce length.
const headerLen = len(magic) + 1 + 12

// Sealed wraps an encrypted backup and the facts about it worth reporting.
type Sealed struct {
	// Bytes is the sealed backup, ready to store.
	Bytes []byte

	// PlainSize is the size of the backup before sealing, for reporting.
	PlainSize int64

	// SHA256 is the hex digest of Bytes, so an operator can compare what was
	// stored against what a destination reports.
	SHA256 string
}

// Seal encrypts a backup with AES-256-GCM under key.
//
// The key must be 32 bytes, derived from the service secret - see
// InfoBackupEncryption. The nonce is random per backup rather than derived,
// because two backups of the same database are near-identical plaintexts and
// reusing a nonce under one key would leak their difference.
func Seal(key, plaintext []byte) (Sealed, error) {
	if len(key) != 32 {
		return Sealed{}, fmt.Errorf("backup: sealing key is %d bytes, want 32", len(key))
	}

	if len(plaintext) == 0 {
		return Sealed{}, errors.New("backup: nothing to seal")
	}

	if int64(len(plaintext)) > MaxBackupBytes {
		return Sealed{}, fmt.Errorf(
			"%w: %d bytes exceeds the %d-byte limit; the notification outbox is the usual cause, "+
				"so check `outbox status --dead` and discard what is no longer needed",
			ErrTooLarge, len(plaintext), MaxBackupBytes)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return Sealed{}, fmt.Errorf("backup: build cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Sealed{}, fmt.Errorf("backup: build GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Sealed{}, fmt.Errorf("backup: read nonce: %w", err)
	}

	header := make([]byte, 0, headerLen)
	header = append(header, magic[:]...)
	header = append(header, formatVersion)
	header = append(header, nonce...)

	// The header is the additional authenticated data, so the version and
	// nonce are covered by the tag: an attacker cannot downgrade the declared
	// version or swap the nonce without the open failing.
	sealed := aead.Seal(header, nonce, plaintext, header)

	digest := sha256.Sum256(sealed)

	return Sealed{
		Bytes:     sealed,
		PlainSize: int64(len(plaintext)),
		SHA256:    hex.EncodeToString(digest[:]),
	}, nil
}

// Unseal decrypts a sealed backup.
//
// The error distinguishes "this is not one of ours", "this is a newer format"
// and "this will not decrypt", because an operator restoring a backup needs to
// know which of those they are looking at. All three otherwise present as the
// same opaque authentication failure.
func Unseal(key, sealed []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("backup: sealing key is %d bytes, want 32", len(key))
	}

	if len(sealed) == 0 {
		return nil, ErrEmpty
	}

	if len(sealed) < headerLen {
		return nil, errors.New("backup: too short to be a netory backup")
	}

	if [6]byte(sealed[:len(magic)]) != magic {
		return nil, errors.New(
			"backup: not a netory backup - the file does not carry the expected header")
	}

	version := sealed[len(magic)]
	if version != formatVersion {
		return nil, fmt.Errorf(
			"backup: unknown format version %d, this build understands %d - the backup was probably "+
				"written by a newer protean", version, formatVersion)
	}

	header := sealed[:headerLen]
	nonce := sealed[len(magic)+1 : headerLen]
	ciphertext := sealed[headerLen:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backup: build cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backup: build GCM: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, errors.New(
			"backup: could not decrypt - either the service secret is not the one this backup was " +
				"made with, or the backup is corrupt. A backup is only restorable with the secret " +
				"that made it")
	}

	return plaintext, nil
}
