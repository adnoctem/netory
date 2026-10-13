package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/adnoctem/netory/internal/signpost/app"
	"github.com/adnoctem/netory/internal/signpost/server"
	"github.com/adnoctem/netory/pkg/admin"
)

// adminClient runs the admin handler on a real Unix socket and returns a
// client for it.
//
// A real socket rather than an httptest server, and the whole publish path is
// the reason: a bundle crosses it as a multipart body of up to 64 MiB, which
// is exactly the kind of thing that works against an in-process handler and
// then fails against a socket. The peer credentials the audit record needs
// also only exist on a real connection.
func adminClient(t *testing.T, h *harness) *admin.Client {
	t.Helper()

	srv, err := admin.NewServer(admin.ServerOptions{
		Path:    h.socketPath(t, "client"),
		Handler: h.srv.AdminHandler(),
		Logger:  silentLogger(t),
	})
	require.NoError(t, err)

	go func() { _ = srv.Serve() }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = srv.Shutdown(ctx)
	})

	client, err := admin.NewClient(admin.ClientOptions{Path: srv.Path(), Timeout: 30 * time.Second})
	require.NoError(t, err)

	return client
}

func TestAdminPublishOverTheSocket(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	archive := bundleFor(t, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	var result server.PublishResponse
	require.NoError(t, client.PostMultipart(ctx, server.APIPrefix+"/bundles", nil,
		[]admin.Upload{{Field: server.FieldArchive, Filename: "bundle.tar.gz", Content: archive}},
		&result))

	asrt := assert.New(t)
	asrt.Equal("1.0.0", result.Release.Release)
	asrt.Len(result.Release.Routes, 1)
	asrt.Equal("/install.sh.sha256", result.Release.Routes[0].ChecksumPath)
	asrt.Equal("/v1.0.0/install.sh", result.Release.Routes[0].VersionedPath)
	asrt.True(result.Release.Serving)
	require.Len(t, result.Moved, 1)
	asrt.Equal(app.DefaultAlias, result.Moved[0].Name)

	// The audit identity comes from the kernel, not from the request. Under
	// the test runner that is the test's own uid, which is all this can check
	// - but it checks that something real arrived rather than "unknown".
	asrt.NotEqual("unknown", result.Release.PublishedBy)

	// And the script is now actually being served.
	assert.Equal(t, http.StatusOK, get(t, h.srv, "/install.sh").Code)
}

func TestAdminPublishRejectsADuplicateRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	archive := bundleFor(t, "1.0.0", map[string]string{"/install.sh": "  echo hello"})
	upload := []admin.Upload{{Field: server.FieldArchive, Filename: "b.tar.gz", Content: archive}}

	require.NoError(t, client.PostMultipart(ctx, server.APIPrefix+"/bundles", nil, upload, nil))

	err := client.PostMultipart(ctx, server.APIPrefix+"/bundles", nil, upload, nil)
	require.Error(t, err)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)

	assert.Equal(t, http.StatusConflict, adminErr.Status)
	assert.Contains(t, adminErr.Hint, "immutable",
		"the hint has to say why republishing is refused, or it reads as a bug")
}

// A malformed bundle is the caller's problem, not the server's, so it must not
// come back as a 5xx: an operator reading "500" looks at the service, and the
// problem is in their hands.
func TestAdminPublishReportsABadBundleAs422(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	for label, archive := range map[string][]byte{
		"not an archive": []byte("this is not an archive"),
		"empty":          {},
		"a gzip of junk": gzipOf(t, "not a tar at all"),
	} {
		t.Run(label, func(t *testing.T) {
			t.Parallel()

			err := client.PostMultipart(ctx, server.APIPrefix+"/bundles", nil,
				[]admin.Upload{{Field: server.FieldArchive, Filename: "b", Content: archive}}, nil)
			require.Error(t, err)

			var adminErr *admin.Error
			require.ErrorAs(t, err, &adminErr)

			assert.Equal(t, http.StatusUnprocessableEntity, adminErr.Status)
		})
	}
}

func TestAdminValidateDoesNotPublish(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	archive := bundleFor(t, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	var report server.ValidateResponse
	require.NoError(t, client.PostMultipart(ctx, server.APIPrefix+"/bundles/validate", nil,
		[]admin.Upload{{Field: server.FieldArchive, Filename: "b.tar.gz", Content: archive}},
		&report))

	asrt := assert.New(t)
	asrt.Equal("1.0.0", report.Release)
	asrt.False(report.Exists)
	asrt.Len(report.Routes, 1)

	releases, err := h.state.Releases.List(ctx)
	require.NoError(t, err)
	asrt.Empty(releases, "validate must not publish anything")

	// Published, and the same validation now reports the name as taken.
	require.NoError(t, client.PostMultipart(ctx, server.APIPrefix+"/bundles", nil,
		[]admin.Upload{{Field: server.FieldArchive, Filename: "b.tar.gz", Content: archive}}, nil))

	report = server.ValidateResponse{}
	require.NoError(t, client.PostMultipart(ctx, server.APIPrefix+"/bundles/validate", nil,
		[]admin.Upload{{Field: server.FieldArchive, Filename: "b.tar.gz", Content: archive}},
		&report))

	asrt.True(report.Exists)
}

func TestAdminAliasAndRollback(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	for _, release := range []string{"1.0.0", "1.1.0"} {
		require.NoError(t, client.PostMultipart(ctx, server.APIPrefix+"/bundles", nil,
			[]admin.Upload{{
				Field:    server.FieldArchive,
				Filename: "b.tar.gz",
				Content:  bundleFor(t, release, map[string]string{"/install.sh": "  echo " + release}),
			}}, nil))
	}

	var aliases []server.AliasResponse
	require.NoError(t, client.Get(ctx, server.APIPrefix+"/aliases", &aliases))
	require.Len(t, aliases, 1)

	asrt := assert.New(t)
	asrt.Equal("1.1.0", aliases[0].Release)
	asrt.Equal("1.0.0", aliases[0].Previous)
	asrt.True(aliases[0].Serving)

	var rolled server.AliasResponse
	require.NoError(t, client.Post(ctx, server.APIPrefix+"/bundles/rollback",
		server.RollbackRequest{}, &rolled))
	asrt.Equal("1.0.0", rolled.Release)

	asrt.Contains(get(t, h.srv, "/install.sh").Body.String(), "echo 1.0.0")

	// A second alias pointed by hand, and removal of the one that is not
	// serving.
	var stable server.AliasResponse
	require.NoError(t, client.Put(ctx, server.APIPrefix+"/aliases/stable",
		server.AliasRequest{Release: "1.1.0"}, &stable))
	asrt.Equal("1.1.0", stable.Release)

	require.NoError(t, client.Delete(ctx, server.APIPrefix+"/aliases/stable"))

	// The serving alias is refused, because removing it would stop every
	// unversioned route being served.
	err := client.Delete(ctx, server.APIPrefix+"/aliases/"+app.DefaultAlias)
	require.Error(t, err)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)
	asrt.Equal(http.StatusConflict, adminErr.Status)
}

func TestAdminRemoveRelease(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	for _, release := range []string{"1.0.0", "1.1.0"} {
		require.NoError(t, client.PostMultipart(ctx, server.APIPrefix+"/bundles", nil,
			[]admin.Upload{{
				Field:    server.FieldArchive,
				Filename: "b.tar.gz",
				Content:  bundleFor(t, release, map[string]string{"/install.sh": "  echo " + release}),
			}}, nil))
	}

	// 1.1.0 is serving, so it cannot go.
	err := client.Delete(ctx, server.APIPrefix+"/bundles/1.1.0")
	require.Error(t, err)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)
	assert.Equal(t, http.StatusConflict, adminErr.Status)

	// 1.0.0 is only reachable on its versioned path, so it can.
	require.NoError(t, client.Delete(ctx, server.APIPrefix+"/bundles/1.0.0"))

	assert.Equal(t, http.StatusNotFound, get(t, h.srv, "/v1.0.0/install.sh").Code)
}

func TestAdminConfigRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	var listed []server.SettingResponse
	require.NoError(t, client.Get(ctx, server.APIPrefix+"/config", &listed))
	require.NotEmpty(t, listed)

	for _, entry := range listed {
		assert.NotEmpty(t, entry.Help, "setting %s has no description", entry.Name)
	}

	var updated server.SettingResponse
	require.NoError(t, client.Put(ctx, server.APIPrefix+"/config/"+app.SettingCacheAliasMaxAge,
		server.SettingRequest{Value: "5s"}, &updated))
	assert.Equal(t, "5s", updated.Value)

	// Applied at once, and visible in what the public listener sends.
	publish(t, h.state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})
	assert.Contains(t, get(t, h.srv, "/install.sh").Header().Get("Cache-Control"), "max-age=5")

	// A rejected value changes nothing.
	err := client.Put(ctx, server.APIPrefix+"/config/"+app.SettingCacheAliasMaxAge,
		server.SettingRequest{Value: "not a duration"}, nil)
	require.Error(t, err)

	var entry server.SettingResponse
	require.NoError(t, client.Get(ctx, server.APIPrefix+"/config/"+app.SettingCacheAliasMaxAge, &entry))
	assert.Equal(t, "5s", entry.Value)
}

// publish.signing_key is parsed before it is stored, so a mistyped key fails
// at `config set` rather than at the next publish - which, with
// require_signature set, is when publishing stops working for reasons that
// look nothing like a typo.
func TestAdminRejectsABadSigningKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	err := client.Put(ctx, server.APIPrefix+"/config/"+app.SettingSigningKey,
		server.SettingRequest{Value: "not-a-minisign-key"}, nil)
	require.Error(t, err)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)
	assert.Equal(t, http.StatusBadRequest, adminErr.Status)

	// A real one is accepted. This is jedisct1's minisign release key, used
	// here only as a well-formed public key.
	require.NoError(t, client.Put(ctx, server.APIPrefix+"/config/"+app.SettingSigningKey,
		server.SettingRequest{
			Value: "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3", //gitleaks:allow
		}, nil))
}

func TestAdminConfigurationView(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	publish(t, h.state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	var view server.ConfigurationResponse
	require.NoError(t, client.Get(ctx, server.APIPrefix+"/configuration", &view))

	asrt := assert.New(t)
	asrt.NotEmpty(view.Bootstrap["listen"])
	asrt.NotEmpty(view.Settings[app.SettingServeAlias])
	asrt.Equal("1.0.0", view.Serving["release"])
	asrt.Equal("1", view.Serving["routes"])

	// Every setting the application layer knows about appears, so `config
	// view` cannot silently omit a new one.
	for _, name := range app.SettingNames() {
		asrt.Contains(view.Settings, name)
	}
}

func TestAdminMeta(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	publish(t, h.state, "1.0.0", map[string]string{"/install.sh": "  echo hello"})

	var meta server.MetaResponse
	require.NoError(t, client.Get(ctx, server.APIPrefix+"/meta", &meta))

	asrt := assert.New(t)
	asrt.Equal(app.Name, meta.Name)
	asrt.Equal(app.DefaultAlias, meta.ServingAlias)
	asrt.Equal("1.0.0", meta.ServingRelease)
	asrt.Equal(1, meta.ServingRoutes)
	asrt.NotEmpty(meta.Notifiers)
	asrt.NotEmpty(meta.ContentStore)
}

func TestAdminUnknownEndpoint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	err := client.Get(ctx, server.APIPrefix+"/nothing-here", nil)
	require.Error(t, err)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)

	assert.Equal(t, http.StatusNotFound, adminErr.Status)
	assert.Contains(t, adminErr.Hint, "version",
		"a 404 on the admin socket is almost always a CLI/server version mismatch")
}

// A publish with no archive part is the CLI's bug, not the bundle's, so it is
// a 400 rather than a 422.
func TestAdminPublishWithoutAnArchive(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newHarness(t, nil)
	client := adminClient(t, h)

	err := client.PostMultipart(ctx, server.APIPrefix+"/bundles",
		map[string]string{server.FieldNoAlias: "true"}, nil, nil)
	require.Error(t, err)

	var adminErr *admin.Error
	require.ErrorAs(t, err, &adminErr)
	assert.Equal(t, http.StatusBadRequest, adminErr.Status)
}

// The public listener is read-only: no path on it changes anything, which is
// what makes "local-only publishing" a property of the code rather than a
// convention. Asserted by firing the admin API's own paths at it.
func TestPublicListenerExposesNoAdminPath(t *testing.T) {
	t.Parallel()

	h := newHarness(t, nil)

	for _, path := range []string{
		server.APIPrefix + "/bundles",
		server.APIPrefix + "/aliases",
		server.APIPrefix + "/config",
		server.APIPrefix + "/meta",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			req := httptest.NewRequest(method, path, nil)
			req.TLS = tlsState()

			recorder := httptest.NewRecorder()
			h.srv.PublicHandler().ServeHTTP(recorder, req)

			assert.NotEqual(t, http.StatusOK, recorder.Code,
				"%s %s must not be served by the public listener", method, path)
		}
	}
}
