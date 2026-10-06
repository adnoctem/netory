package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// localDestination stores backups in a filesystem directory.
//
// This is what air-gapped operation uses, and the ordinary case of writing a
// backup next to the service before shipping it elsewhere.
type localDestination struct {
	dir string
}

// enforce implementation of the interface
var _ Destination = (*localDestination)(nil)

// backupDirMode is the permission a created backup directory gets, and
// backupFileMode the permission of each backup.
//
// 0700 and 0600: a sealed backup is not readable without the service secret,
// but it is still a complete copy of every credential the service holds, and
// there is no reason for anyone but the service user to be able to read the
// ciphertext at all.
const (
	backupDirMode  os.FileMode = 0o700
	backupFileMode os.FileMode = 0o600
)

// openLocal prepares a filesystem destination, creating the directory when it
// does not exist.
func openLocal(dir string) (Destination, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("backup: resolve %q: %w", dir, err)
	}

	info, err := os.Stat(abs)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(abs, backupDirMode); err != nil {
			return nil, fmt.Errorf("backup: create %q: %w", abs, err)
		}
	case err != nil:
		return nil, fmt.Errorf("backup: stat %q: %w", abs, err)
	case !info.IsDir():
		return nil, fmt.Errorf("backup: %q exists and is not a directory", abs)
	}

	return &localDestination{dir: abs}, nil
}

func (l *localDestination) Describe() string { return l.dir }

// Put writes a backup, atomically.
//
// Written to a temporary file in the same directory and renamed into place, so
// an interrupted write leaves no partial backup behind. A truncated backup is
// worse than no backup: it looks like one in a listing, and only fails when
// someone finally needs it.
func (l *localDestination) Put(ctx context.Context, name string, data []byte) error {
	if err := validateName(name); err != nil {
		return err
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	final := filepath.Join(l.dir, name)

	temp, err := os.CreateTemp(l.dir, "."+name+".partial-*")
	if err != nil {
		return fmt.Errorf("backup: create a temporary file in %q: %w", l.dir, err)
	}

	tempName := temp.Name()
	defer func() {
		// Harmless when the rename succeeded; removes the partial file when
		// anything below failed.
		_ = os.Remove(tempName)
	}()

	if err := temp.Chmod(backupFileMode); err != nil {
		_ = temp.Close()

		return fmt.Errorf("backup: restrict %q: %w", tempName, err)
	}

	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()

		return fmt.Errorf("backup: write %q: %w", tempName, err)
	}

	// Synced before the rename. Without this the rename can be durable while
	// the contents are not, which on a crash produces exactly the truncated
	// backup the temporary file was meant to prevent.
	if err := temp.Sync(); err != nil {
		_ = temp.Close()

		return fmt.Errorf("backup: sync %q: %w", tempName, err)
	}

	if err := temp.Close(); err != nil {
		return fmt.Errorf("backup: close %q: %w", tempName, err)
	}

	if err := os.Rename(tempName, final); err != nil {
		return fmt.Errorf("backup: publish %q: %w", final, err)
	}

	return nil
}

// Get reads a stored backup.
func (l *localDestination) Get(ctx context.Context, name string) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	path := filepath.Join(l.dir, name)

	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("%w: %s in %s", ErrNotFound, name, l.dir)
	case err != nil:
		return nil, fmt.Errorf("backup: stat %q: %w", path, err)
	case info.Size() == 0:
		return nil, fmt.Errorf("%w: %s", ErrEmpty, name)
	case info.Size() > MaxBackupBytes:
		return nil, fmt.Errorf("%w: %s is %d bytes", ErrTooLarge, name, info.Size())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("backup: read %q: %w", path, err)
	}

	return data, nil
}

// List returns the stored backups, newest first.
func (l *localDestination) List(ctx context.Context) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	items, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, fmt.Errorf("backup: list %q: %w", l.dir, err)
	}

	entries := make([]Entry, 0, len(items))
	for _, item := range items {
		if item.IsDir() {
			continue
		}

		// Partial writes in progress, and anything else that is not a backup.
		if validateName(item.Name()) != nil || filepath.Ext(item.Name()) != ".backup" {
			continue
		}

		info, err := item.Info()
		if err != nil {
			// A file that vanished between the listing and the stat is not an
			// error worth failing the whole listing over.
			continue
		}

		entries = append(entries, Entry{
			Name:    item.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().UTC(),
		})
	}

	sortEntries(entries)

	return entries, nil
}

// sortEntries orders backups newest first, which is the order an operator
// restoring one wants: the most recent is almost always the answer.
func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].ModTime.Equal(entries[j].ModTime) {
			return entries[i].ModTime.After(entries[j].ModTime)
		}

		// Names embed a sortable timestamp, so they are the tiebreak when
		// modification times match - which they do for several backups written
		// in the same second, and for every object in some S3 setups.
		return entries[i].Name > entries[j].Name
	})
}
