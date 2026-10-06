package bundle_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/signpost/bundle"
)

// A manifest and a script that pass validation, so a test can vary one thing.
const (
	goodManifest = `version: 1
release: 1.4.0
routes:
  - path: /install.sh
    file: scripts/install.sh
`
	goodScript = `#!/bin/sh
main() {
    echo installing
}
main "$@"
`
)

// entry is one file to put in a test archive.
type entry struct {
	name    string
	content string

	// mode, when non-zero, overrides the regular-file mode - used to plant a
	// symlink in a zip.
	mode fs.FileMode

	// typeflag, when non-zero, overrides the tar entry type.
	typeflag byte

	// linkname is the target for a symlink or hardlink entry.
	linkname string
}

// buildZip assembles a zip archive from entries.
func buildZip(t *testing.T, entries ...entry) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for _, e := range entries {
		header := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			header.SetMode(e.mode)
		}

		f, err := w.CreateHeader(header)
		require.NoError(t, err)

		_, err = f.Write([]byte(e.content))
		require.NoError(t, err)
	}

	require.NoError(t, w.Close())

	return buf.Bytes()
}

// buildTarGz assembles a gzipped tar from entries.
func buildTarGz(t *testing.T, entries ...entry) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	w := tar.NewWriter(gz)

	for _, e := range entries {
		typeflag := e.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}

		header := &tar.Header{
			Name:     e.name,
			Mode:     0o644,
			Size:     int64(len(e.content)),
			Typeflag: typeflag,
			Linkname: e.linkname,
		}

		if typeflag != tar.TypeReg {
			header.Size = 0
		}

		require.NoError(t, w.WriteHeader(header))

		if typeflag == tar.TypeReg {
			_, err := w.Write([]byte(e.content))
			require.NoError(t, err)
		}
	}

	require.NoError(t, w.Close())
	require.NoError(t, gz.Close())

	return buf.Bytes()
}

// goodEntries is a minimal valid bundle.
func goodEntries() []entry {
	return []entry{
		{name: "signpost.yaml", content: goodManifest},
		{name: "scripts/install.sh", content: goodScript},
	}
}

func TestOpenAcceptsBothFormats(t *testing.T) {
	asrt := assert.New(t)

	for name, data := range map[string][]byte{
		"zip":    buildZip(t, goodEntries()...),
		"tar.gz": buildTarGz(t, goodEntries()...),
	} {
		archive, err := bundle.Open(data)
		require.NoError(t, err, name)

		asrt.Equal("1.4.0", archive.Manifest.Release, name)
		asrt.Equal("signpost.yaml", archive.ManifestName, name)
		require.Len(t, archive.Manifest.Routes, 1, name)
		asrt.Equal("/install.sh", archive.Manifest.Routes[0].Path, name)
		asrt.Len(archive.SHA256, 64, name)
		asrt.Positive(archive.Size, name)

		// The extracted file is present with its digest.
		file := archive.Files["scripts/install.sh"]
		require.NotNil(t, file, name)
		asrt.Equal(goodScript, string(file.Content), name)
		asrt.Len(file.SHA256, 64, name)
	}
}

// The format is sniffed from the leading bytes, not taken from a filename: the
// name is a hint supplied alongside the bytes, and a mismatch between the two
// is exactly the confusion worth not having.
func TestDetectFormat(t *testing.T) {
	asrt := assert.New(t)

	asrt.Equal(bundle.FormatZip, bundle.DetectFormat(buildZip(t, goodEntries()...)))
	asrt.Equal(bundle.FormatTarGz, bundle.DetectFormat(buildTarGz(t, goodEntries()...)))
	asrt.Equal(bundle.FormatUnknown, bundle.DetectFormat([]byte("just some text")))
	asrt.Equal(bundle.FormatUnknown, bundle.DetectFormat(nil))

	_, err := bundle.Open([]byte("not an archive at all"))
	asrt.Error(err)
	asrt.Contains(err.Error(), ".zip and .tar.gz")
}

// Zip-slip, in every form worth refusing. Names are rejected rather than
// cleaned: cleaning "../../etc/passwd" into "etc/passwd" turns a hostile entry
// into a plausible one.
func TestRejectsPathTraversal(t *testing.T) {
	asrt := assert.New(t)

	for _, name := range []string{
		"../escape.sh",
		"../../etc/passwd",
		"scripts/../../escape.sh",
		"/absolute.sh",
		"/etc/passwd",
		`C:\windows\system32\evil.exe`,
		`scripts\windows.sh`,
		"./relative.sh",
		"scripts//double.sh",
		"",
	} {
		hostile := append(goodEntries(), entry{name: name, content: "payload"})

		_, zipErr := bundle.Open(buildZip(t, hostile...))
		asrt.Error(zipErr, "zip entry %q must be refused", name)

		_, tarErr := bundle.Open(buildTarGz(t, hostile...))
		asrt.Error(tarErr, "tar entry %q must be refused", name)
	}
}

// §6.1 rejects symlinks and hardlinks outright. A symlink can point anywhere
// on the server's filesystem and a hardlink can alias a file outside the
// bundle; neither has a legitimate use in a bundle of scripts.
func TestRejectsLinks(t *testing.T) {
	asrt := assert.New(t)

	symlinked := append(goodEntries(), entry{
		name: "scripts/evil.sh", typeflag: tar.TypeSymlink, linkname: "/etc/passwd",
	})

	_, err := bundle.Open(buildTarGz(t, symlinked...))
	asrt.Error(err)
	asrt.Contains(err.Error(), "symlink")

	withHardLink := append(goodEntries(), entry{
		name: "scripts/evil.sh", typeflag: tar.TypeLink, linkname: "/etc/shadow",
	})

	_, err = bundle.Open(buildTarGz(t, withHardLink...))
	asrt.Error(err)
	asrt.Contains(err.Error(), "hardlink")

	// A zip carries the symlink bit in its Unix mode.
	zipSymlink := append(goodEntries(), entry{
		name: "scripts/evil.sh", content: "/etc/passwd", mode: fs.ModeSymlink | 0o777,
	})

	_, err = bundle.Open(buildZip(t, zipSymlink...))
	asrt.Error(err)
	asrt.Contains(err.Error(), "symlink")
}

// A tar entry that is neither a regular file, a directory nor a link - a
// device node, a FIFO - is refused rather than skipped, so an archive cannot
// carry anything whose meaning depends on the extractor.
func TestRejectsIrregularEntries(t *testing.T) {
	asrt := assert.New(t)

	for _, typeflag := range []byte{tar.TypeChar, tar.TypeBlock, tar.TypeFifo} {
		hostile := append(goodEntries(), entry{name: "scripts/odd", typeflag: typeflag})

		_, err := bundle.Open(buildTarGz(t, hostile...))
		asrt.Error(err, "tar type %q must be refused", string(typeflag))
	}
}

// A decompression bomb: a small archive that expands past the limit. The
// limits are checked against bytes actually read, never against a size the
// archive declares about itself.
func TestRejectsDecompressionBomb(t *testing.T) {
	asrt := assert.New(t)

	// A single entry larger than the per-file limit. Highly compressible, so
	// the archive itself stays small - which is the whole trick.
	huge := strings.Repeat("A", bundle.MaxFileBytes+1024)

	bomb := append(goodEntries(), entry{name: "scripts/bomb.txt", content: huge})

	_, err := bundle.Open(buildZip(t, bomb...))
	asrt.Error(err)
	asrt.Contains(err.Error(), "per-file limit")

	_, err = bundle.Open(buildTarGz(t, bomb...))
	asrt.Error(err)
}

// Many entries that individually fit but together exceed the total.
func TestRejectsTotalExpansionLimit(t *testing.T) {
	asrt := assert.New(t)

	chunk := strings.Repeat("A", bundle.MaxFileBytes-1)

	entries := goodEntries()
	// Enough chunks to pass MaxTotalBytes while each stays under MaxFileBytes.
	for i := 0; i < (bundle.MaxTotalBytes/bundle.MaxFileBytes)+2; i++ {
		entries = append(entries, entry{
			name:    "scripts/chunk" + string(rune('a'+i)) + ".txt",
			content: chunk,
		})
	}

	_, err := bundle.Open(buildTarGz(t, entries...))
	asrt.Error(err)
}

func TestRejectsTooManyEntries(t *testing.T) {
	asrt := assert.New(t)

	entries := goodEntries()
	for i := 0; i <= bundle.MaxEntries; i++ {
		entries = append(entries, entry{
			name:    "scripts/f" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + itoa(i) + ".txt",
			content: "x",
		})
	}

	_, err := bundle.Open(buildZip(t, entries...))
	asrt.Error(err)
	asrt.Contains(err.Error(), "entries")
}

// itoa avoids importing strconv for one call in a test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}

	return string(digits)
}

// Two entries with the same name is ambiguous about which one a route serves,
// and some archive writers emit duplicates deliberately so different readers
// disagree. Refusing is the only answer that cannot be exploited.
func TestRejectsDuplicateEntries(t *testing.T) {
	asrt := assert.New(t)

	duplicated := []entry{
		{name: "signpost.yaml", content: goodManifest},
		{name: "scripts/install.sh", content: goodScript},
		{name: "scripts/install.sh", content: "#!/bin/sh\nrm -rf /\n"},
	}

	_, err := bundle.Open(buildZip(t, duplicated...))
	asrt.Error(err)
	asrt.Contains(err.Error(), "more than once")

	_, err = bundle.Open(buildTarGz(t, duplicated...))
	asrt.Error(err)
}

func TestManifestDiscovery(t *testing.T) {
	asrt := assert.New(t)

	// No manifest.
	_, err := bundle.Open(buildZip(t, entry{name: "scripts/install.sh", content: goodScript}))
	asrt.ErrorIs(err, bundle.ErrNoManifest)

	// Two manifests is ambiguous rather than "pick the first": which one wins
	// is not a contract anyone should have to learn.
	_, err = bundle.Open(buildZip(t,
		entry{name: "signpost.yaml", content: goodManifest},
		entry{name: "signpost.json", content: `{"version":1,"release":"1.0.0","routes":[{"path":"/i.sh","file":"scripts/install.sh"}]}`},
		entry{name: "scripts/install.sh", content: goodScript},
	))
	asrt.ErrorIs(err, bundle.ErrMultipleManifests)

	// A manifest somewhere other than the root is not the manifest.
	_, err = bundle.Open(buildZip(t,
		entry{name: "nested/signpost.yaml", content: goodManifest},
		entry{name: "scripts/install.sh", content: goodScript},
	))
	asrt.ErrorIs(err, bundle.ErrNoManifest)

	// JSON works too.
	archive, err := bundle.Open(buildZip(t,
		entry{name: "signpost.json", content: `{"version":1,"release":"1.0.0","routes":[{"path":"/install.sh","file":"scripts/install.sh"}]}`},
		entry{name: "scripts/install.sh", content: goodScript},
	))
	asrt.NoError(err)
	if archive != nil {
		asrt.Equal("signpost.json", archive.ManifestName)
	}
}

// A route must name a file that was actually extracted, checked against the
// extracted set rather than the archive's own index.
func TestRejectsRouteWithMissingFile(t *testing.T) {
	asrt := assert.New(t)

	_, err := bundle.Open(buildZip(t,
		entry{name: "signpost.yaml", content: goodManifest},
		entry{name: "scripts/other.sh", content: goodScript},
	))
	asrt.Error(err)
	asrt.Contains(err.Error(), "not in the archive")
}

func TestRejectsRouteWithEmptyFile(t *testing.T) {
	asrt := assert.New(t)

	_, err := bundle.Open(buildZip(t,
		entry{name: "signpost.yaml", content: goodManifest},
		entry{name: "scripts/install.sh", content: ""},
	))
	asrt.Error(err)
	asrt.Contains(err.Error(), "empty")
}

func TestRejectsOversizedArchive(t *testing.T) {
	asrt := assert.New(t)

	_, err := bundle.Open(make([]byte, bundle.MaxArchiveBytes+1))
	asrt.Error(err)
	asrt.Contains(err.Error(), "limit")

	_, err = bundle.Open(nil)
	asrt.Error(err)
}

func TestRejectsDeeplyNestedEntries(t *testing.T) {
	asrt := assert.New(t)

	deep := strings.Repeat("a/", bundle.MaxPathDepth+2) + "script.sh"

	_, err := bundle.Open(buildZip(t, append(goodEntries(),
		entry{name: deep, content: goodScript})...))
	asrt.Error(err)
	asrt.Contains(err.Error(), "nested")
}

// Directory entries carry no content and are implied by the files inside them,
// so they are skipped rather than represented.
func TestDirectoryEntriesAreSkipped(t *testing.T) {
	asrt := assert.New(t)

	archive, err := bundle.Open(buildTarGz(t,
		entry{name: "scripts/", typeflag: tar.TypeDir},
		entry{name: "signpost.yaml", content: goodManifest},
		entry{name: "scripts/install.sh", content: goodScript},
	))
	require.NoError(t, err)

	asrt.Equal([]string{"scripts/install.sh", "signpost.yaml"}, archive.Names())
}
