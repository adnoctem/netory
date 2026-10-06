package bundle

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// Limits on an archive, enforced while unpacking.
//
// Every one of these exists because the archive is attacker-shaped input that
// must be unpacked before anything in it can be validated. Without them a
// small upload can cost unbounded memory or disk: a few kilobytes of gzip
// expands to gigabytes of zeros, and a zip central directory can claim
// millions of entries.
const (
	// MaxArchiveBytes bounds the compressed archive.
	MaxArchiveBytes = 64 << 20 // 64 MiB

	// MaxTotalBytes bounds the sum of all uncompressed entries. This is the
	// decompression-bomb limit: it is checked against bytes actually read, not
	// against any size the archive declares about itself.
	MaxTotalBytes = 256 << 20 // 256 MiB

	// MaxFileBytes bounds one entry. A shell script is kilobytes; a megabyte
	// is already generous and anything larger is not what this service is for.
	MaxFileBytes = 8 << 20 // 8 MiB

	// MaxEntries bounds how many entries are read.
	MaxEntries = 4096

	// MaxPathDepth bounds nesting inside the archive.
	MaxPathDepth = 16
)

// File is one extracted file, held in memory.
//
// Bundles are small by construction - MaxTotalBytes caps the lot - and keeping
// them in memory means nothing hostile is written to the filesystem until the
// whole bundle has passed validation. That is the staging requirement in §6.1,
// achieved by not staging on disk at all: a malicious archive never touches
// the live tree, nor any tree.
type File struct {
	// Name is the entry's path inside the archive, canonical and relative.
	Name string

	// Content is the entry's bytes.
	Content []byte

	// SHA256 is the hex digest of Content.
	SHA256 string
}

// Archive is an unpacked bundle.
type Archive struct {
	// Manifest is the parsed, validated manifest.
	Manifest *Manifest

	// ManifestName is which of ManifestNames was found.
	ManifestName string

	// Files are the extracted entries, keyed by archive path.
	Files map[string]*File

	// SHA256 is the digest of the archive as supplied, which is what a
	// signature covers and what the audit log records.
	SHA256 string

	// Size is the archive's size in bytes.
	Size int64
}

// Format identifies an archive container.
type Format string

// The supported archive formats.
const (
	FormatZip     Format = "zip"
	FormatTarGz   Format = "tar.gz"
	FormatUnknown Format = ""
)

// DetectFormat identifies an archive from its leading bytes.
//
// Sniffed rather than taken from the filename: the filename is a hint supplied
// alongside the bytes, and a mismatch between the two is exactly the sort of
// confusion worth not having. A caller may pass the name for the error
// message, but it does not decide how the bytes are read.
func DetectFormat(data []byte) Format {
	switch {
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 0x03, 0x04}):
		return FormatZip
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 0x05, 0x06}):
		// An empty zip's end-of-central-directory record. Recognised so the
		// error says "the archive is empty" rather than "unknown format".
		return FormatZip
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		return FormatTarGz
	default:
		return FormatUnknown
	}
}

// Open unpacks and validates an archive.
//
// Validation order matters and is deliberate: the container is unpacked with
// every limit enforced, then the manifest is found and parsed, then the
// manifest is validated, then every route is checked against what was actually
// extracted. Nothing is written anywhere and nothing is published until all of
// it passes, which is what makes a rejected bundle rejected whole.
func Open(data []byte) (*Archive, error) {
	if len(data) == 0 {
		return nil, errors.New("bundle: the archive is empty")
	}

	if int64(len(data)) > MaxArchiveBytes {
		return nil, fmt.Errorf(
			"bundle: the archive is %d bytes, the limit is %d", len(data), MaxArchiveBytes)
	}

	digest := sha256.Sum256(data)

	var (
		files map[string]*File
		err   error
	)

	format := DetectFormat(data)
	switch format {
	case FormatZip:
		files, err = extractZip(data)
	case FormatTarGz:
		files, err = extractTarGz(data)
	default:
		return nil, errors.New(
			"bundle: unrecognised archive format - signpost accepts .zip and .tar.gz")
	}

	if err != nil {
		return nil, err
	}

	archive := &Archive{
		Files:  files,
		SHA256: hex.EncodeToString(digest[:]),
		Size:   int64(len(data)),
	}

	if err := archive.loadManifest(); err != nil {
		return nil, err
	}

	if err := archive.Manifest.Validate(); err != nil {
		return nil, err
	}

	if err := archive.checkRoutes(); err != nil {
		return nil, err
	}

	return archive, nil
}

// loadManifest finds and parses the single manifest at the archive root.
func (a *Archive) loadManifest() error {
	var found []string
	for _, name := range ManifestNames {
		if _, ok := a.Files[name]; ok {
			found = append(found, name)
		}
	}

	switch len(found) {
	case 0:
		return fmt.Errorf("%w: expected one of %s", ErrNoManifest, strings.Join(ManifestNames, ", "))
	case 1:
	default:
		// Ambiguous rather than "pick the first": which one wins is not a
		// contract anyone should have to learn.
		return fmt.Errorf("%w: found %s", ErrMultipleManifests, strings.Join(found, ", "))
	}

	name := found[0]

	manifest, err := ParseManifest(name, a.Files[name].Content)
	if err != nil {
		return err
	}

	a.Manifest, a.ManifestName = manifest, name

	return nil
}

// checkRoutes confirms every route names a file that was actually extracted.
//
// This is validation step 3 of §4.2, and it is checked against the extracted
// set rather than against the archive's own index - so an entry the extractor
// skipped or rejected cannot be referenced by a route that then serves
// nothing.
func (a *Archive) checkRoutes() error {
	for i := range a.Manifest.Routes {
		route := &a.Manifest.Routes[i]

		file, ok := a.Files[route.File]
		if !ok {
			return fmt.Errorf(
				"bundle: route %d (%s) references %q, which is not in the archive",
				i, route.Path, route.File)
		}

		if len(file.Content) == 0 {
			return fmt.Errorf(
				"bundle: route %d (%s) references %q, which is empty",
				i, route.Path, route.File)
		}
	}

	return nil
}

// RouteFiles returns the extracted file behind each route, in manifest order.
func (a *Archive) RouteFiles() []*File {
	files := make([]*File, 0, len(a.Manifest.Routes))
	for i := range a.Manifest.Routes {
		files = append(files, a.Files[a.Manifest.Routes[i].File])
	}

	return files
}

// Names returns the extracted entry names, sorted, for diagnostics.
func (a *Archive) Names() []string {
	names := make([]string, 0, len(a.Files))
	for name := range a.Files {
		names = append(names, name)
	}
	sort.Strings(names)

	return names
}

// extractZip unpacks a zip archive.
func extractZip(data []byte) (map[string]*File, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("bundle: the zip archive is malformed: %w", err)
	}

	if len(reader.File) > MaxEntries {
		return nil, fmt.Errorf(
			"bundle: the archive declares %d entries, the limit is %d", len(reader.File), MaxEntries)
	}

	files := make(map[string]*File, len(reader.File))
	var total int64

	for _, entry := range reader.File {
		// Directories carry no content and are implied by the entries inside
		// them, so they are skipped rather than represented.
		if entry.FileInfo().IsDir() {
			continue
		}

		// A zip entry has no type bits for a symlink in the portable sense,
		// but the Unix mode in the external attributes does. A symlink's
		// "content" is its target, so extracting one would silently store a
		// path where a script was expected.
		if entry.Mode()&modeSymlink != 0 {
			return nil, fmt.Errorf("bundle: %q is a symlink, which is not allowed in a bundle", entry.Name)
		}

		if !entry.Mode().IsRegular() {
			return nil, fmt.Errorf("bundle: %q is not a regular file", entry.Name)
		}

		name, err := sanitiseEntryName(entry.Name)
		if err != nil {
			return nil, err
		}

		opened, err := entry.Open()
		if err != nil {
			return nil, fmt.Errorf("bundle: could not read %q: %w", name, err)
		}

		content, err := readEntry(opened, name, &total)
		_ = opened.Close()

		if err != nil {
			return nil, err
		}

		if err := addFile(files, name, content); err != nil {
			return nil, err
		}
	}

	if len(files) == 0 {
		return nil, errors.New("bundle: the archive contains no files")
	}

	return files, nil
}

// extractTarGz unpacks a gzipped tar archive.
func extractTarGz(data []byte) (map[string]*File, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("bundle: the gzip stream is malformed: %w", err)
	}
	defer func() { _ = gz.Close() }()

	// The tar stream is read through a limited reader as well as the per-entry
	// accounting below. gzip will happily produce far more output than its
	// input, and the tar headers themselves are part of that expansion.
	reader := tar.NewReader(io.LimitReader(gz, MaxTotalBytes+1))

	files := make(map[string]*File, 16)
	var (
		total   int64
		entries int
	)

	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("bundle: the tar archive is malformed: %w", err)
		}

		entries++
		if entries > MaxEntries {
			return nil, fmt.Errorf("bundle: more than %d entries", MaxEntries)
		}

		switch header.Typeflag {
		case tar.TypeReg:
		case tar.TypeDir:
			continue
		case tar.TypeSymlink, tar.TypeLink:
			// §6.1 rejects both outright. A symlink can point anywhere on the
			// server's filesystem, and a hardlink can alias a file outside the
			// bundle; neither has any legitimate use in a bundle of scripts.
			return nil, fmt.Errorf(
				"bundle: %q is a %s, which is not allowed in a bundle",
				header.Name, linkKind(header.Typeflag))
		default:
			return nil, fmt.Errorf(
				"bundle: %q is not a regular file (tar type %q)", header.Name, string(header.Typeflag))
		}

		name, err := sanitiseEntryName(header.Name)
		if err != nil {
			return nil, err
		}

		content, err := readEntry(reader, name, &total)
		if err != nil {
			return nil, err
		}

		if err := addFile(files, name, content); err != nil {
			return nil, err
		}
	}

	if len(files) == 0 {
		return nil, errors.New("bundle: the archive contains no files")
	}

	return files, nil
}

// linkKind names a tar link type for an error message.
func linkKind(typeflag byte) string {
	if typeflag == tar.TypeSymlink {
		return "symlink"
	}

	return "hardlink"
}

// readEntry reads one entry, enforcing the per-file and total limits.
//
// The limits are applied to bytes actually read, never to a size the archive
// declares. A zip entry's stated uncompressed size is attacker-controlled, so
// trusting it is how a decompression bomb gets through a size check.
func readEntry(r io.Reader, name string, total *int64) ([]byte, error) {
	limited := io.LimitReader(r, MaxFileBytes+1)

	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("bundle: could not read %q: %w", name, err)
	}

	if int64(len(content)) > MaxFileBytes {
		return nil, fmt.Errorf(
			"bundle: %q is larger than the %d-byte per-file limit", name, MaxFileBytes)
	}

	*total += int64(len(content))
	if *total > MaxTotalBytes {
		return nil, fmt.Errorf(
			"bundle: the archive expands to more than the %d-byte limit", MaxTotalBytes)
	}

	return content, nil
}

// addFile records an extracted entry, rejecting a duplicate name.
//
// Two entries with the same name is ambiguous about which one a route would
// serve, and some archive writers emit duplicates deliberately so that
// different readers disagree. Refusing is the only answer that cannot be
// exploited.
func addFile(files map[string]*File, name string, content []byte) error {
	if _, exists := files[name]; exists {
		return fmt.Errorf("bundle: %q appears more than once in the archive", name)
	}

	digest := sha256.Sum256(content)
	files[name] = &File{
		Name:    name,
		Content: content,
		SHA256:  hex.EncodeToString(digest[:]),
	}

	return nil
}

// sanitiseEntryName validates an archive entry name.
//
// This is the zip-slip defence (§6.1). The name is rejected rather than
// cleaned: cleaning "../../etc/passwd" into "etc/passwd" turns a hostile entry
// into a plausible one, which is how a path-traversal check becomes a
// path-traversal feature.
func sanitiseEntryName(name string) (string, error) {
	if name == "" {
		return "", errors.New("bundle: the archive contains an entry with no name")
	}

	// Backslashes first: a Windows-style separator would make the segment
	// checks below look at one segment where a reader on another platform sees
	// several.
	if strings.Contains(name, `\`) {
		return "", fmt.Errorf("bundle: entry %q must use '/' as its separator", name)
	}

	if strings.ContainsRune(name, 0x00) {
		return "", fmt.Errorf("bundle: entry %q contains a NUL byte", name)
	}

	if strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("bundle: entry %q is an absolute path", name)
	}

	// A drive letter is an absolute path on Windows and would be a plain
	// relative name here, which is exactly the sort of cross-platform
	// disagreement worth refusing.
	if len(name) >= 2 && name[1] == ':' {
		return "", fmt.Errorf("bundle: entry %q looks like an absolute Windows path", name)
	}

	segments := strings.Split(name, "/")
	if len(segments) > MaxPathDepth {
		return "", fmt.Errorf(
			"bundle: entry %q is nested %d deep, the limit is %d", name, len(segments), MaxPathDepth)
	}

	for _, segment := range segments {
		switch segment {
		case "":
			return "", fmt.Errorf("bundle: entry %q contains an empty segment", name)
		case ".":
			return "", fmt.Errorf("bundle: entry %q contains a '.' segment", name)
		case "..":
			return "", fmt.Errorf("bundle: entry %q escapes the archive root", name)
		}
	}

	// Belt and braces: after all the above, the name must already be what
	// path.Clean would produce. If it is not, something was missed.
	if cleaned := path.Clean(name); cleaned != name {
		return "", fmt.Errorf("bundle: entry %q is not a canonical path", name)
	}

	return name, nil
}
