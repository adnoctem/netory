package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/adnoctem/netory/internal/signpost/app"
	"github.com/adnoctem/netory/internal/signpost/bundle"
	"github.com/adnoctem/netory/pkg/admin"
	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/notify"
)

// APIPrefix versions the admin API.
//
// The CLI and the server ship in the same binary, so they normally match - but
// an operator can have an older binary in PATH than the one running as the
// server, and a prefix makes a future incompatible change a new prefix rather
// than a silently misinterpreted request.
const APIPrefix = "/v1"

// Multipart field names for a publish or validate request.
const (
	FieldArchive   = "archive"
	FieldSignature = "signature"
	FieldAliases   = "aliases"
	FieldPublicKey = "public_key"
	FieldNoAlias   = "no_alias"
)

// adminHandler builds the admin routes.
//
// Every route is a thin translation between the CLI's intent and the
// application layer; no logic lives here that app does not already own. That
// keeps the socket surface auditable: the interesting question about an admin
// API is what it exposes, and this file is the answer in full.
func (s *Server) adminHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET "+APIPrefix+"/meta", s.adminMeta)

	// Publishing and validation both take a multipart body, because a bundle
	// is up to 64 MiB of binary and admin.DecodeJSON bounds a request at 8.
	mux.HandleFunc("POST "+APIPrefix+"/bundles", s.adminBundlePublish)
	mux.HandleFunc("POST "+APIPrefix+"/bundles/validate", s.adminBundleValidate)
	mux.HandleFunc("POST "+APIPrefix+"/bundles/rollback", s.adminBundleRollback)
	mux.HandleFunc("GET "+APIPrefix+"/bundles", s.adminBundleList)
	mux.HandleFunc("GET "+APIPrefix+"/bundles/{release}", s.adminBundleGet)
	mux.HandleFunc("DELETE "+APIPrefix+"/bundles/{release}", s.adminBundleRemove)

	mux.HandleFunc("GET "+APIPrefix+"/aliases", s.adminAliasList)
	mux.HandleFunc("PUT "+APIPrefix+"/aliases/{name}", s.adminAliasSet)
	mux.HandleFunc("DELETE "+APIPrefix+"/aliases/{name}", s.adminAliasRemove)

	mux.HandleFunc("GET "+APIPrefix+"/notifiers", s.adminNotifierList)
	mux.HandleFunc("POST "+APIPrefix+"/notifiers", s.adminNotifierAdd)
	mux.HandleFunc("DELETE "+APIPrefix+"/notifiers/{name}", s.adminNotifierRemove)
	mux.HandleFunc("POST "+APIPrefix+"/notifiers/{name}/test", s.adminNotifierTest)

	// A distinct path rather than /config/view, which Go's mux would otherwise
	// have to disambiguate against /config/{name}.
	mux.HandleFunc("GET "+APIPrefix+"/configuration", s.adminConfigurationView)

	mux.HandleFunc("GET "+APIPrefix+"/config", s.adminConfigList)
	mux.HandleFunc("GET "+APIPrefix+"/config/{name}", s.adminConfigGet)
	mux.HandleFunc("PUT "+APIPrefix+"/config/{name}", s.adminConfigSet)

	mux.HandleFunc("GET "+APIPrefix+"/outbox", s.adminOutboxList)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		admin.WriteError(w, admin.Errorf(http.StatusNotFound, "no such admin endpoint: %s %s",
			r.Method, r.URL.Path).
			WithHint("this usually means the CLI is a different version from the running server"))
	})

	return mux
}

// MetaResponse is what `signpost version` reports about the running server.
type MetaResponse struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	CommitSHA string `json:"commit_sha"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`

	// Notifiers are the compiled-in kinds, so `version` can tell an operator
	// what this binary supports without a separate call.
	Notifiers []string `json:"notifiers"`

	// What the public listener is serving right now, which is the one thing an
	// operator checking a running signpost actually wants to know.
	ServingAlias   string `json:"serving_alias"`
	ServingRelease string `json:"serving_release"`
	ServingRoutes  int    `json:"serving_routes"`
	Releases       int    `json:"releases"`

	// ContentStore is where the served bytes live.
	ContentStore string `json:"content_store"`

	// CacheEntries and CacheBytes report the content cache's occupancy.
	CacheEntries int   `json:"cache_entries"`
	CacheBytes   int64 `json:"cache_bytes"`
	CacheBudget  int64 `json:"cache_budget"`
}

func (s *Server) adminMeta(w http.ResponseWriter, _ *http.Request) {
	stamps := s.state.Stamp
	table := s.state.Table()
	entries, bytes, budget := s.state.CacheStats()

	admin.WriteJSON(w, http.StatusOK, MetaResponse{
		Name:           app.Name,
		Version:        stamps.Version,
		CommitSHA:      stamps.CommitSHA,
		BuildDate:      stamps.BuildDate,
		GoVersion:      stamps.GoVersion,
		Platform:       stamps.Platform,
		Notifiers:      notify.Kinds(),
		ServingAlias:   table.Alias,
		ServingRelease: table.Release,
		ServingRoutes:  table.Len(),
		Releases:       len(table.Releases()),
		ContentStore:   s.state.Content.Describe(),
		CacheEntries:   entries,
		CacheBytes:     bytes,
		CacheBudget:    budget,
	})
}

// RouteResponse is one published route.
type RouteResponse struct {
	Path          string `json:"path"`
	File          string `json:"file"`
	ContentType   string `json:"content_type"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	ChecksumPath  string `json:"checksum_path"`
	VersionedPath string `json:"versioned_path"`
}

// ReleaseResponse is one release as the CLI renders it.
type ReleaseResponse struct {
	Release       string          `json:"release"`
	Description   string          `json:"description,omitempty"`
	Routes        []RouteResponse `json:"routes"`
	ArchiveSHA256 string          `json:"archive_sha256"`
	ArchiveSize   int64           `json:"archive_size"`
	ManifestName  string          `json:"manifest_name"`
	Signature     string          `json:"signature"`
	SignatureKey  string          `json:"signature_key,omitempty"`
	SignatureNote string          `json:"signature_note,omitempty"`

	// TruncationSkipped names routes published without the §6.3 check. It is
	// in the list output rather than only in the stored record because a
	// bundle that skipped the check must stay visible afterwards.
	TruncationSkipped []string `json:"truncation_skipped,omitempty"`

	PublishedAt time.Time `json:"published_at"`
	PublishedBy string    `json:"published_by"`

	// Aliases are the aliases currently pointing at this release, and Serving
	// reports whether it is the one the public listener is using.
	Aliases []string `json:"aliases,omitempty"`
	Serving bool     `json:"serving"`
}

// releaseResponse renders a release, with the aliases pointing at it.
func releaseResponse(release app.Release, aliases []string, serving bool) ReleaseResponse {
	routes := make([]RouteResponse, 0, len(release.Routes))
	for _, route := range release.Routes {
		routes = append(routes, RouteResponse{
			Path:          route.Path,
			File:          route.File,
			ContentType:   route.ContentType,
			SHA256:        route.SHA256,
			Size:          route.Size,
			ChecksumPath:  route.Path + bundle.ChecksumSuffix,
			VersionedPath: app.VersionedPath(release.Release, route.Path),
		})
	}

	return ReleaseResponse{
		Release:           release.Release,
		Description:       release.Description,
		Routes:            routes,
		ArchiveSHA256:     release.ArchiveSHA256,
		ArchiveSize:       release.ArchiveSize,
		ManifestName:      release.ManifestName,
		Signature:         release.Signature.Status(),
		SignatureKey:      release.Signature.KeyID,
		SignatureNote:     release.Signature.TrustedComment,
		TruncationSkipped: release.TruncationSkipped,
		PublishedAt:       release.PublishedAt,
		PublishedBy:       release.PublishedBy,
		Aliases:           aliases,
		Serving:           serving,
	}
}

// PublishResponse is what `bundle publish` reports.
type PublishResponse struct {
	Release ReleaseResponse `json:"release"`

	// Moved are the aliases that now point at the new release.
	Moved []AliasResponse `json:"moved,omitempty"`
}

func (s *Server) adminBundlePublish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, err := s.publishRequest(w, r)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	result, err := s.state.PublishBundle(ctx, req)
	if err != nil {
		admin.WriteError(w, publishError(err))

		return
	}

	aliases := make([]AliasResponse, 0, len(result.Moved))
	names := make([]string, 0, len(result.Moved))

	for _, alias := range result.Moved {
		aliases = append(aliases, aliasResponse(alias))
		names = append(names, alias.Name)
	}

	serving := s.state.Table().Release == result.Release.Release

	admin.WriteJSON(w, http.StatusCreated, PublishResponse{
		Release: releaseResponse(result.Release, names, serving),
		Moved:   aliases,
	})
}

// ValidateResponse is what `bundle validate` reports when the server did the
// validating.
type ValidateResponse struct {
	Release     string          `json:"release"`
	Description string          `json:"description,omitempty"`
	Routes      []RouteResponse `json:"routes"`
	ArchiveSize int64           `json:"archive_size"`

	// Exists reports whether this release name is already published, which is
	// the one way a bundle can be valid and still not publishable.
	Exists bool `json:"exists"`

	ArchiveSHA256 string   `json:"archive_sha256"`
	ManifestName  string   `json:"manifest_name"`
	Signature     string   `json:"signature"`
	SignatureKey  string   `json:"signature_key,omitempty"`
	Skipped       []string `json:"truncation_skipped,omitempty"`
}

func (s *Server) adminBundleValidate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, err := s.publishRequest(w, r)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	archive, signature, err := s.state.Validate(ctx, req)
	if err != nil {
		admin.WriteError(w, publishError(err))

		return
	}

	exists, err := s.state.Releases.Exists(ctx, archive.Manifest.Release)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	routes := make([]RouteResponse, 0, len(archive.Manifest.Routes))

	var skipped []string

	for i := range archive.Manifest.Routes {
		route := &archive.Manifest.Routes[i]
		file := archive.Files[route.File]

		routes = append(routes, RouteResponse{
			Path:          route.Path,
			File:          route.File,
			ContentType:   route.ContentTypeFor(),
			SHA256:        file.SHA256,
			Size:          int64(len(file.Content)),
			ChecksumPath:  route.ChecksumPath(),
			VersionedPath: app.VersionedPath(archive.Manifest.Release, route.Path),
		})

		if route.SkipTruncationCheck {
			skipped = append(skipped, route.Path)
		}
	}

	admin.WriteJSON(w, http.StatusOK, ValidateResponse{
		Release:       archive.Manifest.Release,
		Description:   archive.Manifest.Description,
		Routes:        routes,
		ArchiveSize:   archive.Size,
		Exists:        exists,
		ArchiveSHA256: archive.SHA256,
		ManifestName:  archive.ManifestName,
		Signature:     signature.Status(),
		SignatureKey:  signature.KeyID,
		Skipped:       skipped,
	})
}

// publishRequest reads a multipart publish or validate request.
func (s *Server) publishRequest(w http.ResponseWriter, r *http.Request) (app.PublishRequest, error) {
	// The limit is the archive limit plus room for the signature and the text
	// fields. Enforced on the bytes actually read, so an oversized body is cut
	// off rather than buffered and then rejected.
	limit := int64(bundle.MaxArchiveBytes) + (1 << 20)

	form, err := admin.ParseUpload(w, r, limit)
	if err != nil {
		return app.PublishRequest{}, err
	}
	defer func() {
		if form != nil {
			_ = form.RemoveAll()
		}
	}()

	filename, archive, ok, err := admin.UploadedFile(form, FieldArchive)
	if err != nil {
		return app.PublishRequest{}, err
	}

	if !ok {
		return app.PublishRequest{}, admin.Errorf(http.StatusBadRequest,
			"no %s part in the request", FieldArchive).
			WithHint("this is a bug in the CLI rather than something you can fix in the request")
	}

	_, signature, _, err := admin.UploadedFile(form, FieldSignature)
	if err != nil {
		return app.PublishRequest{}, err
	}

	var aliases []string
	for _, name := range strings.Split(admin.UploadedField(form, FieldAliases), ",") {
		if name = strings.TrimSpace(name); name != "" {
			aliases = append(aliases, name)
		}
	}

	return app.PublishRequest{
		Archive:   archive,
		Filename:  filename,
		Signature: signature,
		PublicKey: admin.UploadedField(form, FieldPublicKey),
		Aliases:   aliases,
		NoAlias:   admin.UploadedField(form, FieldNoAlias) == "true",
		By:        peerName(r),
	}, nil
}

// publishError maps an application error to a status an operator can read.
//
// Validation failures are 422 rather than 400: the request was well-formed and
// the CLI did nothing wrong, the bundle did - and the distinction tells an
// operator whether to look at their command or at their bundle.
func publishError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, app.ErrReleaseExists):
		return admin.Errorf(http.StatusConflict, "%v", err).
			WithHint("a release is immutable: bump the release in the manifest, " +
				"or remove the existing one with `signpost bundle remove`")
	case errors.Is(err, app.ErrSignatureRequired):
		return admin.Errorf(http.StatusUnprocessableEntity, "%v", err).
			WithHint("sign the bundle with `minisign -Sm <bundle>` and publish it with --signature")
	case errors.Is(err, app.ErrNoSigningKey):
		return admin.Errorf(http.StatusUnprocessableEntity, "%v", err).
			WithHint("set one with `signpost config set publish.signing_key <key>`, " +
				"or pass --public-key")
	case errors.Is(err, bundle.ErrKeyMismatch), errors.Is(err, bundle.ErrSignatureInvalid):
		return admin.Errorf(http.StatusUnprocessableEntity, "%v", err).
			WithHint("the bundle is not the one that was signed, or it was signed with another key")
	case errors.Is(err, app.ErrTruncationOptOutRefused):
		return admin.Errorf(http.StatusUnprocessableEntity, "%v", err).
			WithHint("remove skip_truncation_check from the manifest, or allow it with " +
				"`signpost config set publish.allow_truncation_opt_out true`")
	case isTruncation(err):
		return admin.Errorf(http.StatusUnprocessableEntity, "%v", err).
			WithHint("wrap the script's logic in a function invoked on the last line, " +
				"so a truncated download cannot execute part of it")
	case errors.Is(err, bundle.ErrNoManifest), errors.Is(err, bundle.ErrMultipleManifests),
		errors.Is(err, bundle.ErrUnsupportedVersion):
		return admin.Errorf(http.StatusUnprocessableEntity, "%v", err)
	case errors.Is(err, app.ErrReleaseNotFound), errors.Is(err, app.ErrAliasNotFound):
		return admin.Errorf(http.StatusNotFound, "%v", err)
	case errors.Is(err, app.ErrAliasRaced):
		return admin.Errorf(http.StatusConflict, "%v", err).
			WithHint("another publish moved the alias; check `signpost alias list` and retry")
	default:
		// Everything else from the publish path is a rejected bundle rather
		// than a server fault: bundle.Open returns plain errors for the dozens
		// of ways an archive can be malformed, and reporting those as 500
		// would tell an operator to look at the server when the problem is in
		// their hands.
		return admin.Errorf(http.StatusUnprocessableEntity, "%v", err)
	}
}

// isTruncation reports whether err is a §6.3 failure.
func isTruncation(err error) bool {
	var truncation *bundle.TruncationError

	return errors.As(err, &truncation) || errors.Is(err, bundle.ErrUncheckableScript)
}

func (s *Server) adminBundleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	releases, err := s.state.Releases.List(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	aliases, err := s.state.Aliases.List(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	byRelease := map[string][]string{}
	for _, alias := range aliases {
		byRelease[alias.Release] = append(byRelease[alias.Release], alias.Name)
	}

	serving := s.state.Table().Release

	out := make([]ReleaseResponse, 0, len(releases))
	for _, release := range releases {
		out = append(out, releaseResponse(
			release, byRelease[release.Release], release.Release == serving))
	}

	admin.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) adminBundleGet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("release")

	release, err := s.state.Releases.Get(ctx, name)
	if err != nil {
		admin.WriteError(w, publishError(err))

		return
	}

	aliases, err := s.state.Aliases.ReferencedBy(ctx, name)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	admin.WriteJSON(w, http.StatusOK,
		releaseResponse(release, aliases, s.state.Table().Release == name))
}

func (s *Server) adminBundleRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("release")

	if err := s.state.RemoveRelease(ctx, name, peerName(r)); err != nil {
		if errors.Is(err, app.ErrReleaseInUse) {
			admin.WriteError(w, admin.Errorf(http.StatusConflict, "%v", err).
				WithHint("move or remove those aliases first, "+
					"or the routes they serve would resolve to nothing"))

			return
		}

		admin.WriteError(w, publishError(err))

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RollbackRequest is the body of `bundle rollback`.
type RollbackRequest struct {
	// Alias is which alias to roll back. Empty means the serving alias.
	Alias string `json:"alias,omitempty"`
}

func (s *Server) adminBundleRollback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req RollbackRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	name := req.Alias
	if name == "" {
		settings, err := s.state.LoadSettings(ctx)
		if err != nil {
			admin.WriteError(w, err)

			return
		}

		name = settings.ServeAlias
	}

	alias, err := s.state.Rollback(ctx, name, peerName(r))
	if err != nil {
		if errors.Is(err, app.ErrNoPreviousRelease) {
			admin.WriteError(w, admin.Errorf(http.StatusConflict, "%v", err).
				WithHint("signpost keeps one step of history, "+
					"so an alias that has only ever been set once cannot be rolled back. "+
					"Use `signpost alias set` to point it somewhere explicitly"))

			return
		}

		admin.WriteError(w, publishError(err))

		return
	}

	admin.WriteJSON(w, http.StatusOK, aliasResponse(alias))
}

// AliasResponse is one alias as the CLI renders it.
type AliasResponse struct {
	Name      string    `json:"name"`
	Release   string    `json:"release"`
	Previous  string    `json:"previous,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
	Serving   bool      `json:"serving"`
}

func aliasResponse(alias app.Alias) AliasResponse {
	return AliasResponse{
		Name:      alias.Name,
		Release:   alias.Release,
		Previous:  alias.Previous,
		UpdatedAt: alias.UpdatedAt,
		UpdatedBy: alias.UpdatedBy,
	}
}

func (s *Server) adminAliasList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	aliases, err := s.state.Aliases.List(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	serving := s.state.Table().Alias

	out := make([]AliasResponse, 0, len(aliases))
	for _, alias := range aliases {
		rendered := aliasResponse(alias)
		rendered.Serving = alias.Name == serving
		out = append(out, rendered)
	}

	admin.WriteJSON(w, http.StatusOK, out)
}

// AliasRequest is the body of `alias set`.
type AliasRequest struct {
	Release string `json:"release"`
}

func (s *Server) adminAliasSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req AliasRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	if req.Release == "" {
		admin.WriteError(w, admin.Errorf(http.StatusBadRequest, "a release is required"))

		return
	}

	alias, err := s.state.SetAlias(ctx, r.PathValue("name"), req.Release, peerName(r))
	if err != nil {
		admin.WriteError(w, publishError(err))

		return
	}

	admin.WriteJSON(w, http.StatusOK, aliasResponse(alias))
}

func (s *Server) adminAliasRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	// Removing the serving alias stops the unversioned routes being served at
	// all. Allowed - an operator may be retiring an install URL deliberately -
	// but it is a loud enough consequence to name in the refusal, so it is
	// never done by accident on a typo'd name.
	if name == settings.ServeAlias {
		admin.WriteError(w, admin.Errorf(http.StatusConflict,
			"%s is the serving alias: removing it would stop every unversioned route being served", name).
			WithHint("point serve.alias elsewhere first with "+
				"`signpost config set serve.alias <other>`"))

		return
	}

	if err := s.state.RemoveAlias(ctx, name, peerName(r)); err != nil {
		admin.WriteError(w, publishError(err))

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// NotifierRequest is the body of `notifier add`.
type NotifierRequest struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Settings map[string]string `json:"settings"`
}

// TestResponse is the result of a `notifier test`, or of a removal whose
// effect is worth a sentence rather than a bare 204.
type TestResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// NotifierResponse is one notifier, with credentials redacted.
type NotifierResponse struct {
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Settings map[string]string `json:"settings"`
}

func (s *Server) adminNotifierList(w http.ResponseWriter, r *http.Request) {
	configs, err := s.state.Notifiers.List(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	out := make([]NotifierResponse, 0, len(configs))
	for _, cfg := range configs {
		out = append(out, NotifierResponse{
			Name: cfg.Name,
			Kind: cfg.Kind,

			// Redacted by the transport, which is the only thing that knows
			// which of its settings are credentials.
			Settings: cfg.Redacted(),
		})
	}

	admin.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) adminNotifierAdd(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req NotifierRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	cfg := notify.Config{Name: req.Name, Kind: req.Kind, Settings: req.Settings}

	if err := s.state.Notifiers.Add(ctx, cfg, s.state.Secret); err != nil {
		if errors.Is(err, app.ErrNotifierExists) {
			admin.WriteError(w, admin.Errorf(http.StatusConflict, "%v", err))

			return
		}

		admin.WriteError(w, admin.Errorf(http.StatusBadRequest, "%v", err))

		return
	}

	// Subscribed now rather than at the next restart, so a notifier added in
	// response to an incident receives the next event rather than the next
	// event after a restart. Building it again here is cheap and keeps Add's
	// contract - it validates and stores, it does not wire anything up.
	if notifier, err := notify.New(cfg, s.state.Secret); err == nil {
		s.state.Bus.Subscribe(notifier)
	}

	admin.WriteJSON(w, http.StatusCreated, NotifierResponse{
		Name:     cfg.Name,
		Kind:     cfg.Kind,
		Settings: cfg.Redacted(),
	})
}

func (s *Server) adminNotifierRemove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := s.state.Notifiers.Remove(ctx, r.PathValue("name")); err != nil {
		if errors.Is(err, app.ErrNotifierNotFound) {
			admin.WriteError(w, admin.Errorf(http.StatusNotFound, "%v", err))

			return
		}

		admin.WriteError(w, err)

		return
	}

	// The bus keeps the subscription until the next restart. Removing a live
	// subscription would mean the bus holding a mutable registry keyed by
	// name, and the cost of not doing it is one notifier that keeps delivering
	// until restart - which is why the response says so rather than
	// pretending otherwise.
	admin.WriteJSON(w, http.StatusOK, TestResponse{
		OK:      true,
		Message: "notifier removed; it stops receiving events after the next server restart",
	})
}

func (s *Server) adminNotifierTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := r.PathValue("name")

	cfg, err := s.state.Notifiers.Get(ctx, name)
	if err != nil {
		if errors.Is(err, app.ErrNotifierNotFound) {
			admin.WriteError(w, admin.Errorf(http.StatusNotFound, "%v", err))

			return
		}

		admin.WriteError(w, err)

		return
	}

	notifier, err := notify.New(cfg, s.state.Secret)
	if err != nil {
		admin.WriteError(w, admin.Errorf(http.StatusUnprocessableEntity, "%v", err))

		return
	}

	// Delivered synchronously rather than through the outbox: `notifier test`
	// exists to answer "does this work", and an answer that arrives after a
	// retry cycle is not an answer.
	testEvent := event.New(event.Type("notifier.test"), name,
		"This is a test notification from signpost.")

	if err := notifier.Deliver(ctx, testEvent); err != nil {
		// 200 with ok=false rather than a 5xx. The request was handled
		// correctly and the answer is "the transport does not work", which is
		// precisely what `notifier test` was asked to find out - reporting it
		// as a server error would make a successful diagnosis look like a
		// failure of signpost.
		admin.WriteJSON(w, http.StatusOK, TestResponse{
			OK:      false,
			Message: err.Error(),
		})

		return
	}

	admin.WriteJSON(w, http.StatusOK, TestResponse{
		OK:      true,
		Message: "delivered through " + cfg.Kind,
	})
}

// ConfigurationResponse is what `config view` reports: the whole active
// configuration, bootstrap and runtime together.
//
// Both halves in one response because the split between them is signpost's
// implementation detail, not something an operator should have to hold in
// their head to answer "what is this server doing".
type ConfigurationResponse struct {
	// Bootstrap are the values that had to be known before the database could
	// be opened, so they come from the environment and flags.
	Bootstrap map[string]string `json:"bootstrap"`

	// Settings are the database-backed values managed with `config set`.
	Settings map[string]string `json:"settings"`

	// Serving describes what the public listener is currently serving.
	Serving map[string]string `json:"serving"`
}

func (s *Server) adminConfigurationView(w http.ResponseWriter, r *http.Request) {
	settings, err := s.state.LoadSettings(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	table := s.state.Table()

	admin.WriteJSON(w, http.StatusOK, ConfigurationResponse{
		Bootstrap: s.state.Config.Redacted(),
		Settings:  settings.All(),
		Serving: map[string]string{
			"alias":         table.Alias,
			"release":       table.Release,
			"routes":        strconv.Itoa(table.Len()),
			"releases":      strconv.Itoa(len(table.Releases())),
			"content.store": s.state.Content.Describe(),
			"generated":     table.GeneratedAt.Format(time.RFC3339),
		},
	})
}

// SettingResponse is one setting.
type SettingResponse struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Help  string `json:"help,omitempty"`
}

func (s *Server) adminConfigList(w http.ResponseWriter, r *http.Request) {
	settings, err := s.state.LoadSettings(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	values := settings.All()

	out := make([]SettingResponse, 0, len(values))
	for _, name := range app.SettingNames() {
		help, _ := app.SettingHelp(name)
		out = append(out, SettingResponse{Name: name, Value: values[name], Help: help})
	}

	admin.WriteJSON(w, http.StatusOK, out)
}

func (s *Server) adminConfigGet(w http.ResponseWriter, r *http.Request) {
	settings, err := s.state.LoadSettings(r.Context())
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	name := r.PathValue("name")

	value, err := settings.Get(name)
	if err != nil {
		admin.WriteError(w, admin.Errorf(http.StatusNotFound, "%v", err))

		return
	}

	help, _ := app.SettingHelp(name)
	admin.WriteJSON(w, http.StatusOK, SettingResponse{Name: name, Value: value, Help: help})
}

// SettingRequest is the body of `config set`.
type SettingRequest struct {
	Value string `json:"value"`
}

func (s *Server) adminConfigSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req SettingRequest
	if err := admin.DecodeJSON(w, r, &req); err != nil {
		admin.WriteError(w, err)

		return
	}

	settings, err := s.state.LoadSettings(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	name := r.PathValue("name")

	updated, err := settings.Set(name, req.Value)
	if err != nil {
		admin.WriteError(w, admin.Errorf(http.StatusBadRequest, "%v", err))

		return
	}

	if err := s.state.ApplySettings(ctx, updated); err != nil {
		admin.WriteError(w, err)

		return
	}

	value, err := updated.Get(name)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	s.log.Info("setting changed", "setting", name, "value", value, "by", peerName(r))

	help, _ := app.SettingHelp(name)
	admin.WriteJSON(w, http.StatusOK, SettingResponse{Name: name, Value: value, Help: help})
}

// OutboxResponse is the queue's state, as `signpost` reports it.
type OutboxResponse struct {
	Pending int           `json:"pending"`
	Dead    int           `json:"dead"`
	Entries []event.Entry `json:"entries,omitempty"`
}

func (s *Server) adminOutboxList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	pending, dead, err := s.state.Outbox.Counts(ctx)
	if err != nil {
		admin.WriteError(w, err)

		return
	}

	response := OutboxResponse{Pending: pending, Dead: dead}

	// The dead entries are the interesting ones after an incident: a
	// notification that a release was published and never arrived is exactly
	// what an operator goes looking for. The pending ones answer the other
	// question - what is stuck right now.
	switch {
	case r.URL.Query().Get("dead") == "true":
		entries, err := s.state.Outbox.Dead(ctx, outboxPageSize)
		if err != nil {
			admin.WriteError(w, err)

			return
		}

		response.Entries = entries
	case r.URL.Query().Get("pending") == "true":
		entries, err := s.state.Outbox.Pending(ctx, outboxPageSize)
		if err != nil {
			admin.WriteError(w, err)

			return
		}

		response.Entries = entries
	}

	admin.WriteJSON(w, http.StatusOK, response)
}

// outboxPageSize bounds how many entries one `outbox` call returns.
const outboxPageSize = 100

// peerName renders the socket peer for an audit record.
//
// Taken from the kernel through SO_PEERCRED rather than from anything the
// request claimed, which is what makes the "who" in §8.1's audit trail worth
// recording at all.
func peerName(r *http.Request) string {
	peer, ok := admin.PeerFrom(r.Context())
	if !ok {
		return "unknown"
	}

	return peer.String()
}
