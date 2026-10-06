package app

import (
	"os"
	"path/filepath"
)

// SHA256Hex exposes the digest helper to the package's tests, so a test
// computes a content digest the same way the publish path does rather than
// repeating the idiom and risking computing something subtly different.
func SHA256Hex(content []byte) string { return sha256Hex(content) }

// OverwriteForTest replaces a stored object's bytes without updating its name.
//
// This exists to make a tampered file, which is the one state the digest
// verification in Get is there to catch and the one state no public API can
// produce - Put would compute the right name for the new bytes.
func OverwriteForTest(root, release, digest string, content []byte) error {
	return os.WriteFile(filepath.Join(root, release, digest), content, contentFileMode)
}
