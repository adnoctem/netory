// Package backup stores and retrieves encrypted database backups, on the local
// filesystem or in S3.
//
// # Backups of an encrypted database are not themselves encrypted
//
// This is the fact the package exists for. Badger's own backup reads key-value
// pairs through the normal transaction path, which means it reads them
// *decrypted*: a backup of an AES-encrypted Badger directory is a plaintext
// stream of every host, token hash, provider credential and notifier password
// in it. Writing that to a filesystem or an S3 bucket would undo the database
// encryption entirely, and would do so silently.
//
// So every backup this package writes is sealed with AES-256-GCM under a key
// derived from the service secret. The consequence is worth stating plainly: a
// backup is only restorable with the secret that made it. That is the same
// property the database itself has, so it adds no new way to lose data - but it
// does mean the secret has to be backed up somewhere else.
//
// # Destinations
//
// A destination is either a filesystem directory or an S3 prefix. The local one
// covers air-gapped operation and the ordinary "write it next to the service"
// case; S3 covers off-host retention. Both satisfy one interface, so the
// calling code neither knows nor cares which it has.
package backup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Entry is one stored backup.
type Entry struct {
	// Name is the object or file name, which is what Restore takes.
	Name string `json:"name"`

	// Size is the size of the stored (sealed) bytes.
	Size int64 `json:"size"`

	// ModTime is when it was stored.
	ModTime time.Time `json:"mod_time"`
}

// Destination stores and retrieves backups.
//
// It is deliberately small. A backup is written once, listed, and read back
// whole; there is no partial read, no append, and no rename, so nothing here
// needs to express them.
type Destination interface {
	// Put stores data under name.
	Put(ctx context.Context, name string, data []byte) error

	// Get retrieves a stored backup.
	Get(ctx context.Context, name string) ([]byte, error)

	// List returns the stored backups, newest first.
	List(ctx context.Context) ([]Entry, error)

	// Describe renders the destination for a log line or a CLI message, with
	// nothing secret in it.
	Describe() string
}

// MaxBackupBytes bounds a backup, sealed or unsealed.
//
// The limit exists because sealing is a single AES-GCM operation over the whole
// backup, which means it is held in memory. That is a deliberate trade: chunked
// framing would remove the limit at the cost of a bespoke format to get wrong,
// and the data protean stores - hosts, token hashes, credentials, settings and
// an outbox - is kilobytes to low megabytes. A gigabyte is several orders of
// magnitude of headroom.
//
// If a database ever does exceed this, the outbox is almost certainly why, and
// the error says so.
const MaxBackupBytes = 1 << 30 // 1 GiB

// Sentinel errors.
var (
	// ErrNotFound is returned when a named backup does not exist.
	ErrNotFound = errors.New("backup: not found")

	// ErrTooLarge is returned when a backup exceeds MaxBackupBytes.
	ErrTooLarge = errors.New("backup: too large")

	// ErrEmpty is returned when a stored backup has no contents, which means
	// a previous write was interrupted.
	ErrEmpty = errors.New("backup: stored backup is empty")
)

// s3Scheme prefixes an S3 destination.
const s3Scheme = "s3://"

// Open resolves a destination string.
//
// `s3://bucket/optional/prefix` selects S3; anything else is a filesystem
// path. A path rather than a `file://` URL because an operator writing a
// backup target writes a path, and requiring a scheme for the common case
// would be ceremony.
func Open(ctx context.Context, raw string) (Destination, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("backup: a destination is required")
	}

	if strings.HasPrefix(raw, s3Scheme) {
		return openS3(ctx, raw)
	}

	// A bare "bucket/prefix" is a likely mistake - it would silently create a
	// relative directory next to the working directory instead of reaching
	// S3 - so it is caught rather than obeyed.
	if looksLikeS3WithoutScheme(raw) {
		return nil, fmt.Errorf(
			"backup: %q looks like an S3 location but has no scheme; write it as %s%s",
			raw, s3Scheme, raw,
		)
	}

	return openLocal(raw)
}

// looksLikeS3WithoutScheme reports whether a destination is a relative path
// that was probably meant to be an S3 location.
func looksLikeS3WithoutScheme(raw string) bool {
	for _, prefix := range []string{"S3://", "s3:/", "s3:"} {
		if strings.HasPrefix(raw, prefix) {
			return true
		}
	}

	return false
}

// Name builds a backup name that sorts chronologically.
//
// The timestamp is UTC and second-resolution in a form that is both
// lexicographically and chronologically ordered, so a plain directory listing
// or an S3 prefix listing is already in order. The version is included because
// the first question about an old backup is which build wrote it.
func Name(service, version string, at time.Time) string {
	stamp := at.UTC().Format("20060102T150405Z")

	version = sanitiseNameComponent(version)
	if version == "" {
		version = "unknown"
	}

	return fmt.Sprintf("%s-%s-%s.backup", sanitiseNameComponent(service), stamp, version)
}

// sanitiseNameComponent keeps a name component safe as a filename and as an S3
// key: no separators, no spaces, no characters that need quoting in a shell.
func sanitiseNameComponent(value string) string {
	var b strings.Builder

	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}

	return b.String()
}

// validateName rejects a name that could escape its destination.
//
// The name reaches a filesystem path join and an S3 key, and it arrives from an
// operator's command line or from a listing. A ".." in it would read or write
// outside the destination directory, so it is refused rather than cleaned -
// cleaning silently turns a wrong request into a different one.
func validateName(name string) error {
	if name == "" {
		return errors.New("backup: a name is required")
	}

	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return fmt.Errorf("backup: %q must be a plain name with no path separators", name)
	}

	if strings.HasPrefix(name, ".") {
		return fmt.Errorf("backup: %q must not start with a dot", name)
	}

	return nil
}
