package app_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/signpost/app"
	"github.com/adnoctem/netory/internal/signpost/bundle"
	"github.com/adnoctem/netory/internal/signpost/config"
	"github.com/adnoctem/netory/pkg/kv/badgerkv"
	"github.com/adnoctem/netory/pkg/log"
	"github.com/adnoctem/netory/pkg/secret"
)

// publisher is the audit identity the tests publish as, standing in for what
// SO_PEERCRED would supply.
const publisher = "tester(uid=1000 pid=1)"

func silentLogger(t *testing.T) *log.Logger {
	t.Helper()

	return log.New(log.WithOutput(&strings.Builder{}), log.WithLevel(slog.LevelError))
}

// newState builds application state over a real in-memory Badger store and a
// content directory under t.TempDir.
//
// The real store and the real filesystem rather than fakes: the properties
// these tests are about - SetIfAbsent making a release name unique,
// compare-and-swap making an alias move atomic, a digest mismatch being
// caught on read - are properties of those implementations, and a fake would
// assert only that the test's own fake behaves.
func newState(ctx context.Context, t *testing.T) *app.State {
	t.Helper()

	store, err := badgerkv.New(badgerkv.Options{InMemory: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	raw, err := secret.Generate()
	require.NoError(t, err)

	sec, err := secret.Parse(raw)
	require.NoError(t, err)

	cfg := config.Default()
	cfg.Content = t.TempDir()

	state, err := app.New(ctx, app.Options{
		Config: cfg,
		Logger: silentLogger(t),
		Store:  store,
		Secret: sec,
	})
	require.NoError(t, err)

	return state
}

// script is a shell script that passes the truncation check, which every
// fixture needs: a bundle whose scripts fail it would never reach the code
// under test.
func script(body string) string {
	return "#!/bin/sh\nset -eu\n\nmain() {\n" + body + "\n}\n\nmain \"$@\"\n"
}

// manifest renders a minimal manifest for a release.
func manifest(release string, routes ...string) string {
	var out strings.Builder

	out.WriteString("version: 1\nrelease: " + release + "\nroutes:\n")

	for _, route := range routes {
		out.WriteString("  - path: " + route + "\n    file: scripts" + route + "\n")
	}

	return out.String()
}

// tarGzBundle builds a .tar.gz bundle from a set of files.
func tarGzBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buffer bytes.Buffer

	gz := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(gz)

	for name, content := range files {
		require.NoError(t, writer.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}))

		_, err := writer.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, writer.Close())
	require.NoError(t, gz.Close())

	return buffer.Bytes()
}

// zipBundle builds a .zip bundle from a set of files.
func zipBundle(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buffer bytes.Buffer

	writer := zip.NewWriter(&buffer)

	for name, content := range files {
		entry, err := writer.Create(name)
		require.NoError(t, err)

		_, err = entry.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, writer.Close())

	return buffer.Bytes()
}

// simpleBundle is one release serving /install.sh.
func simpleBundle(t *testing.T, release, body string) []byte {
	t.Helper()

	return tarGzBundle(t, map[string]string{
		"signpost.yaml":      manifest(release, "/install.sh"),
		"scripts/install.sh": script(body),
	})
}

func TestPublishBundle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	result, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "1.0.0", "  echo one"),
		By:      publisher,
	})
	require.NoError(t, err)

	asrt := assert.New(t)
	asrt.Equal("1.0.0", result.Release.Release)
	asrt.Len(result.Release.Routes, 1)
	asrt.Equal("/install.sh", result.Release.Routes[0].Path)
	asrt.Equal(publisher, result.Release.PublishedBy)
	asrt.Equal("unsigned", result.Release.Signature.Status())
	asrt.Equal([]string{"/install.sh"}, result.Release.TruncationChecked)
	asrt.Empty(result.Release.TruncationSkipped)

	// The serving alias was created and moved, so the route is live.
	require.Len(t, result.Moved, 1)
	asrt.Equal(app.DefaultAlias, result.Moved[0].Name)
	asrt.Equal("1.0.0", result.Moved[0].Release)
	asrt.Empty(result.Moved[0].Previous, "a first publish has nothing to roll back to")

	table := state.Table()
	asrt.Equal("1.0.0", table.Release)
	asrt.Equal(1, table.Len())

	resolution, ok := table.Resolve("/install.sh")
	require.True(t, ok)
	asrt.Equal("1.0.0", resolution.Release)
	asrt.False(resolution.Versioned)
	asrt.False(resolution.Checksum)

	content, err := state.ServeContent(ctx, resolution)
	require.NoError(t, err)
	asrt.Contains(string(content), "echo one")
}

// A release is immutable, so publishing the same identifier twice is
// refused. This is the property SetIfAbsent exists for.
func TestPublishRefusesAnExistingRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	_, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "1.0.0", "  echo first"),
		By:      publisher,
	})
	require.NoError(t, err)

	_, err = state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "1.0.0", "  echo second"),
		By:      publisher,
	})
	require.ErrorIs(t, err, app.ErrReleaseExists)

	// The first release's bytes are untouched, which is the point of refusing.
	resolution, ok := state.Table().Resolve("/install.sh")
	require.True(t, ok)

	content, err := state.ServeContent(ctx, resolution)
	require.NoError(t, err)
	assert.Contains(t, string(content), "echo first")
}

// Concurrent publishes of the same release name: exactly one must win. Were
// this a read-then-write, both could succeed and one release name would come
// to mean two different sets of bytes.
func TestConcurrentPublishOfOneReleaseName(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	const publishers = 8

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
		conflicts int
	)

	for i := range publishers {
		wg.Add(1)

		go func(n int) {
			defer wg.Done()

			_, err := state.PublishBundle(ctx, app.PublishRequest{
				Archive: simpleBundle(t, "1.0.0", "  echo "+string(rune('a'+n))),
				By:      publisher,
			})

			mu.Lock()
			defer mu.Unlock()

			if err == nil {
				succeeded++
			} else {
				conflicts++
			}
		}(i)
	}

	wg.Wait()

	assert.Equal(t, 1, succeeded, "exactly one publish of a release name may succeed")
	assert.Equal(t, publishers-1, conflicts)
}

func TestPublishAcceptsZipAndTarGz(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for name, archive := range map[string]func(*testing.T) []byte{
		"tar.gz": func(t *testing.T) []byte {
			t.Helper()

			return tarGzBundle(t, map[string]string{
				"signpost.yaml":      manifest("1.0.0", "/install.sh"),
				"scripts/install.sh": script("  echo tar"),
			})
		},
		"zip": func(t *testing.T) []byte {
			t.Helper()

			return zipBundle(t, map[string]string{
				"signpost.yaml":      manifest("1.0.0", "/install.sh"),
				"scripts/install.sh": script("  echo zip"),
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			state := newState(ctx, t)

			result, err := state.PublishBundle(ctx, app.PublishRequest{
				Archive: archive(t),
				By:      publisher,
			})
			require.NoError(t, err)
			assert.Equal(t, "1.0.0", result.Release.Release)
		})
	}
}

// A bundle whose script is not wrapped for truncation is rejected whole,
// and nothing from it is published.
func TestPublishRejectsAnUnwrappedScript(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	archive := tarGzBundle(t, map[string]string{
		"signpost.yaml":      manifest("1.0.0", "/install.sh"),
		"scripts/install.sh": "#!/bin/sh\ncurl https://example.org | tar xz\n",
	})

	_, err := state.PublishBundle(ctx, app.PublishRequest{Archive: archive, By: publisher})
	require.Error(t, err)

	var truncation *bundle.TruncationError
	assert.ErrorAs(t, err, &truncation)

	releases, listErr := state.Releases.List(ctx)
	require.NoError(t, listErr)
	assert.Empty(t, releases, "a rejected bundle must leave nothing behind")

	assert.Equal(t, 0, state.Table().Len())
}

// The opt-out is honoured, recorded, and refusable.
func TestPublishTruncationOptOut(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	archive := tarGzBundle(t, map[string]string{
		"signpost.yaml": "version: 1\nrelease: 1.0.0\nroutes:\n" +
			"  - path: /install.sh\n    file: scripts/install.sh\n    skip_truncation_check: true\n",
		"scripts/install.sh": "#!/bin/sh\ncurl https://example.org | tar xz\n",
	})

	t.Run("recorded when allowed", func(t *testing.T) {
		t.Parallel()

		state := newState(ctx, t)

		result, err := state.PublishBundle(ctx, app.PublishRequest{Archive: archive, By: publisher})
		require.NoError(t, err)

		assert.Equal(t, []string{"/install.sh"}, result.Release.TruncationSkipped)
		assert.Empty(t, result.Release.TruncationChecked)
	})

	t.Run("refused when the instance forbids it", func(t *testing.T) {
		t.Parallel()

		state := newState(ctx, t)

		settings, err := state.LoadSettings(ctx)
		require.NoError(t, err)

		settings.AllowTruncationSkip = false
		require.NoError(t, state.ApplySettings(ctx, settings))

		_, err = state.PublishBundle(ctx, app.PublishRequest{Archive: archive, By: publisher})
		require.ErrorIs(t, err, app.ErrTruncationOptOutRefused)
	})
}

func TestPublishSignaturePolicy(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	archive := func(t *testing.T) []byte {
		t.Helper()

		return simpleBundle(t, "1.0.0", "  echo signed")
	}

	t.Run("required and absent", func(t *testing.T) {
		t.Parallel()

		state := newState(ctx, t)

		settings, err := state.LoadSettings(ctx)
		require.NoError(t, err)

		settings.RequireSignature = true
		require.NoError(t, state.ApplySettings(ctx, settings))

		_, err = state.PublishBundle(ctx, app.PublishRequest{Archive: archive(t), By: publisher})
		require.ErrorIs(t, err, app.ErrSignatureRequired)
	})

	t.Run("supplied with no key to check it against", func(t *testing.T) {
		t.Parallel()

		state := newState(ctx, t)

		// A signature with no trusted key is refused rather than ignored: a
		// publisher who attached one would otherwise have no way to tell it
		// was never checked.
		_, err := state.PublishBundle(ctx, app.PublishRequest{
			Archive:   archive(t),
			Signature: []byte("untrusted comment: x\nnot-a-signature\n"),
			By:        publisher,
		})
		require.ErrorIs(t, err, app.ErrNoSigningKey)
	})

	t.Run("a bad signature is refused", func(t *testing.T) {
		t.Parallel()

		state := newState(ctx, t)

		_, err := state.PublishBundle(ctx, app.PublishRequest{
			Archive:   archive(t),
			Signature: []byte("untrusted comment: x\nnot-a-signature\n"),
			PublicKey: "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3", //gitleaks:allow
			By:        publisher,
		})
		require.Error(t, err)
		assert.NotErrorIs(t, err, app.ErrNoSigningKey)
	})
}

// The ordering property: when a signature is required, the extractor is
// not reached until the bytes are known to come from the trusted key. A
// malformed archive with no signature must therefore fail on the signature,
// not on the archive.
func TestSignatureIsCheckedBeforeExtraction(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	settings, err := state.LoadSettings(ctx)
	require.NoError(t, err)

	settings.RequireSignature = true
	require.NoError(t, state.ApplySettings(ctx, settings))

	_, err = state.PublishBundle(ctx, app.PublishRequest{
		Archive: []byte("this is not an archive at all"),
		By:      publisher,
	})
	require.ErrorIs(t, err, app.ErrSignatureRequired,
		"an unsigned bundle must be refused before its bytes reach the extractor")
}

func TestVersionedRoutesAndStaging(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	// Staged with --no-alias: published, reachable on its versioned path, not
	// serving on the alias path.
	_, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "2.0.0", "  echo staged"),
		NoAlias: true,
		By:      publisher,
	})
	require.NoError(t, err)

	table := state.Table()
	asrt := assert.New(t)

	asrt.Empty(table.Release, "no alias points anywhere yet")

	_, ok := table.Resolve("/install.sh")
	asrt.False(ok, "the unversioned path must not serve a staged release")

	resolution, ok := table.Resolve("/v2.0.0/install.sh")
	require.True(t, ok)
	asrt.True(resolution.Versioned)
	asrt.Equal("2.0.0", resolution.Release)

	// Now point the alias at it, and the unversioned path comes alive.
	_, err = state.SetAlias(ctx, app.DefaultAlias, "2.0.0", publisher)
	require.NoError(t, err)

	_, ok = state.Table().Resolve("/install.sh")
	asrt.True(ok)
}

func TestChecksumResolution(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	_, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "1.0.0", "  echo sum"),
		By:      publisher,
	})
	require.NoError(t, err)

	resolution, ok := state.Table().Resolve("/install.sh.sha256")
	require.True(t, ok)
	assert.True(t, resolution.Checksum)
	assert.Equal(t, "/install.sh", resolution.Route.Path)

	versioned, ok := state.Table().Resolve("/v1.0.0/install.sh.sha256")
	require.True(t, ok)
	assert.True(t, versioned.Checksum)
	assert.True(t, versioned.Versioned)
}

func TestRollback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	for _, release := range []string{"1.0.0", "1.1.0"} {
		_, err := state.PublishBundle(ctx, app.PublishRequest{
			Archive: simpleBundle(t, release, "  echo "+release),
			By:      publisher,
		})
		require.NoError(t, err)
	}

	require.Equal(t, "1.1.0", state.Table().Release)

	rolled, err := state.Rollback(ctx, app.DefaultAlias, publisher)
	require.NoError(t, err)

	asrt := assert.New(t)
	asrt.Equal("1.0.0", rolled.Release)
	asrt.Equal("1.0.0", state.Table().Release)

	// Rollback is its own undo: a second one returns to where the first came
	// from, rather than failing or going further back.
	again, err := state.Rollback(ctx, app.DefaultAlias, publisher)
	require.NoError(t, err)
	asrt.Equal("1.1.0", again.Release)

	resolution, ok := state.Table().Resolve("/install.sh")
	require.True(t, ok)

	content, err := state.ServeContent(ctx, resolution)
	require.NoError(t, err)
	asrt.Contains(string(content), "echo 1.1.0")
}

func TestRollbackWithNoHistory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	_, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "1.0.0", "  echo only"),
		By:      publisher,
	})
	require.NoError(t, err)

	_, err = state.Rollback(ctx, app.DefaultAlias, publisher)
	require.ErrorIs(t, err, app.ErrNoPreviousRelease)
}

func TestRemoveRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	_, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "1.0.0", "  echo one"),
		By:      publisher,
	})
	require.NoError(t, err)

	// Refused while the alias still points at it: the routes it serves would
	// otherwise resolve to nothing.
	err = state.RemoveRelease(ctx, "1.0.0", publisher)
	require.ErrorIs(t, err, app.ErrReleaseInUse)

	_, err = state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "1.1.0", "  echo two"),
		By:      publisher,
	})
	require.NoError(t, err)

	// The alias has moved on, so the old release can go. Its content goes
	// with it.
	require.NoError(t, state.RemoveRelease(ctx, "1.0.0", publisher))

	_, err = state.Releases.Get(ctx, "1.0.0")
	assert.ErrorIs(t, err, app.ErrReleaseNotFound)

	_, ok := state.Table().Resolve("/v1.0.0/install.sh")
	assert.False(t, ok, "a removed release must not stay reachable on its versioned path")

	_, err = state.Content.Get(ctx, "1.0.0", strings.Repeat("0", 64))
	assert.Error(t, err)
}

// Removing the release an alias could roll back to, and then rolling back:
// refused with a message naming the missing release, rather than leaving the
// route table unbuildable.
func TestRollbackOntoARemovedRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	for _, release := range []string{"1.0.0", "1.1.0"} {
		_, err := state.PublishBundle(ctx, app.PublishRequest{
			Archive: simpleBundle(t, release, "  echo "+release),
			By:      publisher,
		})
		require.NoError(t, err)
	}

	require.NoError(t, state.RemoveRelease(ctx, "1.0.0", publisher))

	_, err := state.Rollback(ctx, app.DefaultAlias, publisher)
	require.ErrorIs(t, err, app.ErrReleaseNotFound)

	// Still serving what it was, which is the important part: a refused
	// rollback must not move the alias.
	assert.Equal(t, "1.1.0", state.Table().Release)
}

// Several aliases can point at one release, and publishing moves only the ones
// asked for.
func TestPublishToNamedAliases(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	_, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "1.0.0", "  echo one"),
		Aliases: []string{"latest", "stable"},
		By:      publisher,
	})
	require.NoError(t, err)

	_, err = state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "1.1.0", "  echo two"),
		Aliases: []string{"latest"},
		By:      publisher,
	})
	require.NoError(t, err)

	latest, err := state.Aliases.Get(ctx, "latest")
	require.NoError(t, err)
	assert.Equal(t, "1.1.0", latest.Release)

	stable, err := state.Aliases.Get(ctx, "stable")
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", stable.Release, "an alias not named must not move")
}

// An alias move is a compare-and-swap, so a caller holding a stale read loses
// rather than overwriting a release it never saw.
func TestAliasSwapRefusesAStaleWrite(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	for _, release := range []string{"1.0.0", "1.1.0"} {
		_, err := state.PublishBundle(ctx, app.PublishRequest{
			Archive: simpleBundle(t, release, "  echo "+release),
			NoAlias: true,
			By:      publisher,
		})
		require.NoError(t, err)
	}

	first, err := state.Aliases.Set(ctx, app.Alias{Name: "latest"}, "1.0.0", publisher)
	require.NoError(t, err)

	// Someone else moves it.
	_, err = state.Aliases.Set(ctx, first, "1.1.0", publisher)
	require.NoError(t, err)

	// Our stale read is refused.
	_, err = state.Aliases.Set(ctx, first, "1.0.0", publisher)
	require.ErrorIs(t, err, app.ErrAliasRaced)
}

func TestSetAliasRequiresAnExistingRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	_, err := state.SetAlias(ctx, "latest", "does-not-exist", publisher)
	require.ErrorIs(t, err, app.ErrReleaseNotFound)
}

// Content is stored under its digest and verified on read, so a file altered
// on disk is detected rather than served. This is the guarantee the service
// sells, so it is asserted against a real tampered file.
func TestStorageDetectsTamperedContent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()

	storage, err := app.NewLocalStorage(dir)
	require.NoError(t, err)

	content := []byte("#!/bin/sh\necho original\n")
	digest := app.SHA256Hex(content)

	require.NoError(t, storage.Put(ctx, "1.0.0", digest, content))

	read, err := storage.Get(ctx, "1.0.0", digest)
	require.NoError(t, err)
	assert.Equal(t, content, read)

	// Overwrite the stored object with different bytes under the same name.
	require.NoError(t, app.OverwriteForTest(dir, "1.0.0", digest, []byte("#!/bin/sh\necho altered\n")))

	_, err = storage.Get(ctx, "1.0.0", digest)
	require.ErrorIs(t, err, app.ErrDigestMismatch)
}

func TestStorageRejectsABadDigestOrRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	storage, err := app.NewLocalStorage(t.TempDir())
	require.NoError(t, err)

	for label, call := range map[string]func() error{
		"traversal in the release": func() error {
			return storage.Put(ctx, "../escape", strings.Repeat("a", 64), []byte("x"))
		},
		"traversal in the digest": func() error {
			return storage.Put(ctx, "1.0.0", "../../etc/passwd", []byte("x"))
		},
		"short digest": func() error {
			return storage.Put(ctx, "1.0.0", "abcd", []byte("x"))
		},
		"non-hex digest": func() error {
			return storage.Put(ctx, "1.0.0", strings.Repeat("z", 64), []byte("x"))
		},
	} {
		assert.Error(t, call(), label)
	}
}

func TestMissingObjectIsReported(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	storage, err := app.NewLocalStorage(t.TempDir())
	require.NoError(t, err)

	_, err = storage.Get(ctx, "1.0.0", strings.Repeat("ab", 32))
	require.ErrorIs(t, err, app.ErrObjectNotFound)
}

// Scan returns entries in unspecified order, so List must sort for
// itself. Asserted by publishing out of order and checking the result.
func TestReleaseListIsOrdered(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	for _, release := range []string{"1.0.0", "3.0.0", "2.0.0"} {
		_, err := state.PublishBundle(ctx, app.PublishRequest{
			Archive: simpleBundle(t, release, "  echo "+release),
			NoAlias: true,
			By:      publisher,
		})
		require.NoError(t, err)
	}

	releases, err := state.Releases.List(ctx)
	require.NoError(t, err)
	require.Len(t, releases, 3)

	// Newest first, by publish time.
	assert.Equal(t, "2.0.0", releases[0].Release)
	assert.Equal(t, "1.0.0", releases[2].Release)
}

func TestEventTaxonomyMatchesTheDesignDocument(t *testing.T) {
	t.Parallel()

	// The documented event taxonomy, exactly.
	want := []string{
		"bundle.published",
		"bundle.rejected",
		"alias.changed",
		"bundle.removed",
	}

	got := make([]string, 0, len(app.EventTypes()))
	for _, e := range app.EventTypes() {
		got = append(got, string(e))
	}

	assert.Equal(t, want, got)
}

func TestPublishEmitsEvents(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	_, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive: simpleBundle(t, "1.0.0", "  echo one"),
		By:      publisher,
	})
	require.NoError(t, err)

	pending, err := state.Outbox.Pending(ctx, 100)
	require.NoError(t, err)

	types := map[string]bool{}
	for _, entry := range pending {
		types[string(entry.Event.Type)] = true
	}

	assert.True(t, types["bundle.published"], "a publish must announce itself")
	assert.True(t, types["alias.changed"], "an alias move must announce itself")
}

func TestRejectionEmitsAnEvent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	_, err := state.PublishBundle(ctx, app.PublishRequest{
		Archive: []byte("not an archive"),
		By:      publisher,
	})
	require.Error(t, err)

	pending, listErr := state.Outbox.Pending(ctx, 100)
	require.NoError(t, listErr)

	var found bool

	for _, entry := range pending {
		if entry.Event.Type == app.EventBundleRejected {
			found = true

			assert.Equal(t, "unknown", entry.Event.Subject,
				"a bundle rejected before its manifest was read has no release to name")
		}
	}

	assert.True(t, found, "a rejected bundle must announce itself")
}

// Deduplication is off by default, and the sequence that proves it is the one
// it would otherwise eat: publish, publish, roll back. Three alias.changed
// events for the same alias inside a minute, of which an operator must hear
// all three - the rollback notification is the one that matters most, and
// collapsing on type and subject would drop it.
func TestRollbackIsNotDeduplicatedAway(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	state := newState(ctx, t)

	for _, release := range []string{"1.0.0", "1.1.0"} {
		_, err := state.PublishBundle(ctx, app.PublishRequest{
			Archive: simpleBundle(t, release, "  echo "+release),
			By:      publisher,
		})
		require.NoError(t, err)
	}

	_, err := state.Rollback(ctx, app.DefaultAlias, publisher)
	require.NoError(t, err)

	pending, err := state.Outbox.Pending(ctx, 100)
	require.NoError(t, err)

	var (
		aliasChanges int
		reasons      []string
	)

	for _, entry := range pending {
		if entry.Event.Type == app.EventAliasChanged {
			aliasChanges++
			reasons = append(reasons, entry.Event.Fields["reason"])
		}
	}

	assert.Equal(t, 3, aliasChanges,
		"all three alias moves must be announced, including the rollback")
	assert.Contains(t, reasons, app.ReasonRollback)
	assert.Contains(t, reasons, app.ReasonPublish)
}
