package app

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Storage holds the bytes signpost serves.
//
// Release metadata lives in Badger; the script contents live behind this
// interface, so an S3 backend can be added later without touching the
// serving path. The interface is small for the same reason it was in
// pkg/backup: a release is written once, read back, and deleted whole, so
// nothing here needs to express anything else.
type Storage interface {
	// Put stores one object under a release and returns nothing: the caller
	// already knows the digest, because it is the object's name.
	Put(ctx context.Context, release, digest string, content []byte) error

	// Get retrieves an object.
	Get(ctx context.Context, release, digest string) ([]byte, error)

	// RemoveRelease deletes every object belonging to a release.
	RemoveRelease(ctx context.Context, release string) error

	// Describe renders the backing store for a log line.
	Describe() string
}

// Sentinel errors.
var (
	// ErrObjectNotFound is returned when a stored object is missing, which
	// means the metadata and the storage have diverged.
	ErrObjectNotFound = errors.New("signpost: stored object not found")

	// ErrDigestMismatch is returned when a stored object's bytes do not hash
	// to the name it was stored under.
	ErrDigestMismatch = errors.New("signpost: stored object does not match its digest")
)

// Permissions for the content tree.
//
// 0700 and 0600. The scripts are public - they are served to anyone - but the
// tree is signpost's own state, and a file the service user alone can write is
// one fewer way for the bytes it serves to be altered out from under it.
const (
	contentDirMode  fs.FileMode = 0o700
	contentFileMode fs.FileMode = 0o600
)

// localStorage stores objects in a filesystem tree.
type localStorage struct {
	root string
}

// enforce implementation of the interface
var _ Storage = (*localStorage)(nil)

// NewLocalStorage prepares a filesystem-backed store rooted at dir.
func NewLocalStorage(dir string) (Storage, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("signpost: resolve content directory %q: %w", dir, err)
	}

	info, err := os.Stat(abs)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(abs, contentDirMode); err != nil {
			return nil, fmt.Errorf("signpost: create content directory %q: %w", abs, err)
		}
	case err != nil:
		return nil, fmt.Errorf("signpost: stat content directory %q: %w", abs, err)
	case !info.IsDir():
		return nil, fmt.Errorf("signpost: %q exists and is not a directory", abs)
	}

	return &localStorage{root: abs}, nil
}

func (l *localStorage) Describe() string { return l.root }

// objectPath builds the filesystem path for an object.
//
// Both components are validated rather than trusted. The release comes from a
// manifest and the digest from a hash of extracted bytes, so neither should be
// hostile by the time it arrives - but this is the function that turns them
// into a filesystem path, and a path join is the wrong place to rely on
// something upstream having checked.
func (l *localStorage) objectPath(release, digest string) (string, error) {
	if err := validateStorageComponent(release); err != nil {
		return "", fmt.Errorf("signpost: release %q: %w", release, err)
	}

	if err := validateDigest(digest); err != nil {
		return "", err
	}

	return filepath.Join(l.root, release, digest), nil
}

// validateStorageComponent rejects anything that could escape the root.
func validateStorageComponent(value string) error {
	if value == "" {
		return errors.New("is empty")
	}

	if strings.ContainsAny(value, `/\`) || strings.Contains(value, "..") {
		return errors.New("must be a single path component")
	}

	if strings.HasPrefix(value, ".") {
		return errors.New("must not start with a dot")
	}

	return nil
}

// validateDigest rejects anything that is not a hex SHA-256.
func validateDigest(digest string) error {
	const sha256HexLen = 64

	if len(digest) != sha256HexLen {
		return fmt.Errorf("signpost: digest %q is %d characters, expected %d",
			digest, len(digest), sha256HexLen)
	}

	if _, err := hex.DecodeString(digest); err != nil {
		return fmt.Errorf("signpost: digest %q is not hexadecimal", digest)
	}

	return nil
}

// Put writes an object atomically.
//
// Via a temporary file and a rename, synced first, for the same reason
// pkg/backup does it: a truncated script is worse than a missing one, because
// it looks present and only fails when someone runs it. Here that someone is
// piping it into a shell.
func (l *localStorage) Put(ctx context.Context, release, digest string, content []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	path, err := l.objectPath(release, digest)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, contentDirMode); err != nil {
		return fmt.Errorf("signpost: create release directory %q: %w", dir, err)
	}

	// Already present with the right name means already present with the
	// right bytes, since the name is the digest. Two routes in one bundle
	// serving identical content land here.
	if _, err := os.Stat(path); err == nil {
		return nil
	}

	temp, err := os.CreateTemp(dir, "."+digest+".partial-*")
	if err != nil {
		return fmt.Errorf("signpost: create a temporary file in %q: %w", dir, err)
	}

	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()

	if err := temp.Chmod(contentFileMode); err != nil {
		_ = temp.Close()

		return fmt.Errorf("signpost: restrict %q: %w", tempName, err)
	}

	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()

		return fmt.Errorf("signpost: write %q: %w", tempName, err)
	}

	if err := temp.Sync(); err != nil {
		_ = temp.Close()

		return fmt.Errorf("signpost: sync %q: %w", tempName, err)
	}

	if err := temp.Close(); err != nil {
		return fmt.Errorf("signpost: close %q: %w", tempName, err)
	}

	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("signpost: publish %q: %w", path, err)
	}

	return nil
}

// Get retrieves an object and verifies it against its own name.
//
// The digest check is not redundant. The name is the hash, so a file whose
// bytes no longer match it has been altered since it was written - by disk
// corruption, or by someone with write access to the content tree. signpost's
// entire guarantee is that the code it serves is the code that was published,
// so serving bytes that fail this check would break the one promise the
// service makes.
func (l *localStorage) Get(ctx context.Context, release, digest string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	path, err := l.objectPath(release, digest)
	if err != nil {
		return nil, err
	}

	content, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s/%s", ErrObjectNotFound, release, digest)
		}

		return nil, fmt.Errorf("signpost: read %q: %w", path, err)
	}

	if actual := sha256Hex(content); actual != digest {
		return nil, fmt.Errorf("%w: %s/%s hashes to %s", ErrDigestMismatch, release, digest, actual)
	}

	return content, nil
}

// RemoveRelease deletes a release's whole directory.
func (l *localStorage) RemoveRelease(ctx context.Context, release string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := validateStorageComponent(release); err != nil {
		return fmt.Errorf("signpost: release %q: %w", release, err)
	}

	dir := filepath.Join(l.root, release)

	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("signpost: remove release directory %q: %w", dir, err)
	}

	return nil
}
