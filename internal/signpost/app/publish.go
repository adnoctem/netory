package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adnoctem/netory/internal/signpost/bundle"
)

// Reasons recorded on an alias.changed event, so a reader can tell a routine
// publish from an incident.
const (
	ReasonPublish  = "publish"
	ReasonRollback = "rollback"
	ReasonManual   = "manual"
)

// Sentinel errors for the publish path.
var (
	// ErrSignatureRequired is returned when publish.require_signature is set
	// and no verified signature was supplied.
	ErrSignatureRequired = errors.New("signpost: a verified signature is required to publish")

	// ErrNoSigningKey is returned when a signature was supplied but no public
	// key is configured or given.
	ErrNoSigningKey = errors.New("signpost: no trusted public key to verify the signature against")

	// ErrTruncationOptOutRefused is returned when a manifest opts a route out
	// of the §6.3 check and the instance does not allow it.
	ErrTruncationOptOutRefused = errors.New(
		"signpost: this instance does not allow opting a route out of the truncation check")
)

// PublishRequest is one `bundle publish`.
type PublishRequest struct {
	// Archive is the bundle's bytes.
	Archive []byte

	// Filename is what the operator published, for diagnostics only. It does
	// not decide how the bytes are read; the format is sniffed.
	Filename string

	// Signature is the detached minisign signature, if any.
	Signature []byte

	// PublicKey overrides the configured trusted key for this publish.
	PublicKey string

	// Aliases are the aliases to move to the new release. Empty means the
	// serving alias.
	Aliases []string

	// NoAlias publishes the release without moving any alias, which is how a
	// release is staged for a versioned install before it becomes the default.
	NoAlias bool

	// By is who published, taken from the socket peer rather than from
	// anything the request claimed.
	By string
}

// PublishResult is what a successful publish produced.
type PublishResult struct {
	// Release is the created release.
	Release Release

	// Moved are the aliases that now point at it.
	Moved []Alias
}

// Validate runs the §4.2 validation over an archive without publishing it.
//
// This is what `bundle validate` calls on the server side and what Publish
// calls before it writes anything. The same function in both places is the
// point: §4.2 requires the server's pass to be the one that is trusted, and
// two implementations of "the same validation" would eventually stop being
// the same.
func (s *State) Validate(ctx context.Context, req PublishRequest) (*bundle.Archive, SignatureRecord, error) {
	settings, err := s.Settings.Load(ctx)
	if err != nil {
		return nil, SignatureRecord{}, err
	}

	return s.validate(req, settings)
}

// validate is the shared validation body, taking already-loaded settings.
func (s *State) validate(req PublishRequest, settings Settings) (*bundle.Archive, SignatureRecord, error) {
	if len(req.Archive) == 0 {
		return nil, SignatureRecord{}, errors.New("signpost: the bundle is empty")
	}

	// The signature is checked before the archive is unpacked.
	//
	// Order matters here and it is the one place in the publish path where it
	// is a security property rather than a convenience: the extractor is the
	// component that processes attacker-shaped input (§6.1), so when a
	// signature is required, nothing hostile reaches it until the bytes have
	// been shown to come from the trusted key.
	signature, err := s.verifySignature(req, settings)
	if err != nil {
		return nil, SignatureRecord{}, err
	}

	archive, err := bundle.Open(req.Archive)
	if err != nil {
		return nil, signature, err
	}

	if err := s.checkTruncation(archive, settings); err != nil {
		return nil, signature, err
	}

	return archive, signature, nil
}

// verifySignature applies the signature policy to a publish request.
func (s *State) verifySignature(req PublishRequest, settings Settings) (SignatureRecord, error) {
	key := req.PublicKey
	if key == "" {
		key = settings.SigningKey
	}

	if len(req.Signature) == 0 {
		if settings.RequireSignature {
			return SignatureRecord{}, ErrSignatureRequired
		}

		return SignatureRecord{}, nil
	}

	// A signature was supplied, so it is verified whether or not the instance
	// requires one. Accepting an unverifiable signature as "unsigned" would
	// turn a missing key into a silent downgrade, and the operator who
	// attached it would have no way to tell it had been ignored.
	if key == "" {
		return SignatureRecord{}, ErrNoSigningKey
	}

	sig, err := bundle.VerifyBundle(key, req.Signature, req.Archive)
	if err != nil {
		return SignatureRecord{}, err
	}

	parsed, err := bundle.ParsePublicKey(key)
	if err != nil {
		return SignatureRecord{}, err
	}

	return SignatureRecord{
		Verified:       true,
		KeyID:          parsed.KeyIDHex(),
		TrustedComment: sig.TrustedComment,
		Prehashed:      sig.Prehashed,
	}, nil
}

// checkTruncation applies the §6.3 check to every route of an archive.
func (s *State) checkTruncation(archive *bundle.Archive, settings Settings) error {
	for i := range archive.Manifest.Routes {
		route := &archive.Manifest.Routes[i]

		if route.SkipTruncationCheck {
			if !settings.AllowTruncationSkip {
				return fmt.Errorf("%w: route %s", ErrTruncationOptOutRefused, route.Path)
			}

			continue
		}

		file, ok := archive.Files[route.File]
		if !ok {
			// Unreachable: bundle.Open checks every route resolves. Kept as
			// an error rather than a panic because the alternative to a clear
			// message here is a nil dereference in the publish path.
			return fmt.Errorf("signpost: route %s references %s, which is not in the bundle",
				route.Path, route.File)
		}

		if err := bundle.CheckTruncation(route.File, route.Path, file.Content); err != nil {
			return err
		}
	}

	return nil
}

// PublishBundle validates, stores and publishes a bundle.
//
// The order is the whole of §2's atomicity. Content is written first, then the
// release record, then the aliases, then the route table. Every step is only
// reachable once the one before it succeeded, so at no point does an alias
// name a release whose content is not yet there - a client following an alias
// always lands on something complete.
func (s *State) PublishBundle(ctx context.Context, req PublishRequest) (PublishResult, error) {
	if req.By == "" {
		return PublishResult{}, errors.New("signpost: a publisher is required")
	}

	if err := s.lock(ctx); err != nil {
		return PublishResult{}, err
	}
	defer s.unlock()

	settings, err := s.Settings.Load(ctx)
	if err != nil {
		return PublishResult{}, err
	}

	archive, signature, err := s.validate(req, settings)
	if err != nil {
		s.rejected(ctx, claimedRelease(archive), req.By, err)

		return PublishResult{}, err
	}

	release, err := s.storeRelease(ctx, archive, signature, req.By)
	if err != nil {
		s.rejected(ctx, archive.Manifest.Release, req.By, err)

		return PublishResult{}, err
	}

	moved, err := s.moveAliases(ctx, req, settings, release.Release)
	if err != nil {
		// The release itself is published and its content is stored, so it is
		// reachable on its versioned paths. Not unwound: a release is
		// immutable once created, and deleting it to tidy up a failed alias
		// move would be the one code path that makes a published release
		// disappear. The operator retries the alias move.
		s.Log.Error("published a release but could not move its aliases",
			"release", release.Release, "error", err)

		return PublishResult{}, err
	}

	if err := s.RebuildTable(ctx); err != nil {
		return PublishResult{}, err
	}

	s.Log.Info("release published",
		"release", release.Release,
		"routes", len(release.Routes),
		"archive_sha256", release.ArchiveSHA256,
		"signature", release.Signature.Status(),
		"by", req.By)

	s.Publish(ctx, BundlePublished(release))

	for _, alias := range moved {
		s.Publish(ctx, AliasChanged(alias, ReasonPublish))
	}

	return PublishResult{Release: release, Moved: moved}, nil
}

// claimedRelease returns the release a rejected bundle claimed, if it got far
// enough to claim one.
func claimedRelease(archive *bundle.Archive) string {
	if archive == nil || archive.Manifest == nil {
		return ""
	}

	return archive.Manifest.Release
}

// rejected logs and announces a failed publish.
func (s *State) rejected(ctx context.Context, release, by string, cause error) {
	s.Log.Warn("rejected a bundle",
		"release", release, "by", by, "error", cause)

	s.Publish(ctx, BundleRejected(release, by, cause))
}

// storeRelease writes content then metadata.
//
// Content first, and the release record last, because the release record is
// what makes a release exist: a crash between the two leaves orphaned content
// that nothing references, which is recoverable, whereas the other order
// leaves a release whose bytes are missing, which is not.
func (s *State) storeRelease(
	ctx context.Context,
	archive *bundle.Archive,
	signature SignatureRecord,
	by string,
) (Release, error) {
	manifest := archive.Manifest

	// Refused early so the common case - republishing a release name by
	// mistake - fails before anything is written. Create still checks, and
	// that check is the one that holds under a race.
	exists, err := s.Releases.Exists(ctx, manifest.Release)
	if err != nil {
		return Release{}, err
	}

	if exists {
		return Release{}, fmt.Errorf("%w: %s", ErrReleaseExists, manifest.Release)
	}

	routes := make([]PublishedRoute, 0, len(manifest.Routes))

	var checked, skipped []string

	for i := range manifest.Routes {
		route := &manifest.Routes[i]

		file := archive.Files[route.File]

		if err := s.Content.Put(ctx, manifest.Release, file.SHA256, file.Content); err != nil {
			s.cleanUpContent(ctx, manifest.Release)

			return Release{}, err
		}

		routes = append(routes, PublishedRoute{
			Path:        route.Path,
			File:        route.File,
			ContentType: route.ContentTypeFor(),
			SHA256:      file.SHA256,
			Size:        int64(len(file.Content)),
		})

		if route.SkipTruncationCheck {
			skipped = append(skipped, route.Path)
		} else {
			checked = append(checked, route.Path)
		}
	}

	release := Release{
		Release:           manifest.Release,
		Description:       manifest.Description,
		Routes:            routes,
		ArchiveSHA256:     archive.SHA256,
		ArchiveSize:       archive.Size,
		ManifestName:      archive.ManifestName,
		Signature:         signature,
		TruncationChecked: checked,
		TruncationSkipped: skipped,
		PublishedAt:       time.Now().UTC(),
		PublishedBy:       by,
	}

	if err := s.Releases.Create(ctx, release); err != nil {
		s.cleanUpContent(ctx, manifest.Release)

		return Release{}, err
	}

	return release, nil
}

// cleanUpContent removes a half-written release's content.
//
// Best-effort and logged rather than returned: the caller is already failing,
// and the error it has is more useful than this one. Leftover content is
// harmless - nothing references it - but leaving it silently would make the
// content tree grow for reasons no operator could explain.
func (s *State) cleanUpContent(ctx context.Context, release string) {
	if err := s.Content.RemoveRelease(ctx, release); err != nil {
		s.Log.Error("could not clean up the content of a failed publish",
			"release", release, "error", err)
	}
}

// moveAliases points the requested aliases at a release.
func (s *State) moveAliases(
	ctx context.Context,
	req PublishRequest,
	settings Settings,
	release string,
) ([]Alias, error) {
	if req.NoAlias {
		return nil, nil
	}

	names := req.Aliases
	if len(names) == 0 {
		names = []string{settings.ServeAlias}
	}

	moved := make([]Alias, 0, len(names))
	for _, name := range names {
		alias, err := s.swapAlias(ctx, name, release, req.By)
		if err != nil {
			return moved, err
		}

		moved = append(moved, alias)
	}

	return moved, nil
}

// swapAlias moves one alias, reading it first so the write is a
// compare-and-swap against what was actually there.
func (s *State) swapAlias(ctx context.Context, name, release, by string) (Alias, error) {
	if err := ValidateAlias(name); err != nil {
		return Alias{}, err
	}

	current, err := s.Aliases.Get(ctx, name)
	switch {
	case errors.Is(err, ErrAliasNotFound):
		current = Alias{Name: name}
	case err != nil:
		return Alias{}, err
	}

	return s.Aliases.Set(ctx, current, release, by)
}

// SetAlias points an alias at a release by hand.
//
// The release must exist. Pointing an alias at a release that does not would
// make the route table unbuildable, which is a way to take the public listener
// down with one command.
func (s *State) SetAlias(ctx context.Context, name, release, by string) (Alias, error) {
	if err := s.lock(ctx); err != nil {
		return Alias{}, err
	}
	defer s.unlock()

	if _, err := s.Releases.Get(ctx, release); err != nil {
		return Alias{}, err
	}

	alias, err := s.swapAlias(ctx, name, release, by)
	if err != nil {
		return Alias{}, err
	}

	if err := s.RebuildTable(ctx); err != nil {
		return Alias{}, err
	}

	s.Log.Info("alias moved", "alias", name, "release", release, "by", by)
	s.Publish(ctx, AliasChanged(alias, ReasonManual))

	return alias, nil
}

// RemoveAlias deletes an alias.
func (s *State) RemoveAlias(ctx context.Context, name, by string) error {
	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.unlock()

	if err := s.Aliases.Remove(ctx, name); err != nil {
		return err
	}

	if err := s.RebuildTable(ctx); err != nil {
		return err
	}

	s.Log.Info("alias removed", "alias", name, "by", by)

	return nil
}

// Rollback moves an alias back to the release it pointed at before.
//
// One step, which is what §5 asks for. Rollback exists to undo the publish
// that just broke; a chain nobody prunes would be another thing to reason
// about at the moment reasoning is hardest.
func (s *State) Rollback(ctx context.Context, name, by string) (Alias, error) {
	if err := s.lock(ctx); err != nil {
		return Alias{}, err
	}
	defer s.unlock()

	current, err := s.Aliases.Get(ctx, name)
	if err != nil {
		return Alias{}, err
	}

	if current.Previous == "" {
		return Alias{}, fmt.Errorf("%w: %s", ErrNoPreviousRelease, name)
	}

	// Checked rather than assumed: `bundle remove` refuses a release an alias
	// references, but nothing stops the removal of a release that is only
	// named as an alias's Previous. Rolling back onto a release that no longer
	// exists would make the route table unbuildable.
	if _, err := s.Releases.Get(ctx, current.Previous); err != nil {
		return Alias{}, fmt.Errorf(
			"cannot roll %s back to %s: %w", name, current.Previous, err)
	}

	// The swap sets Previous to what the alias holds now, so a second
	// rollback returns to the release this one left. That makes rollback its
	// own undo, which is the behaviour an operator expects from a command
	// they reached for in a hurry.
	alias, err := s.Aliases.Set(ctx, current, current.Previous, by)
	if err != nil {
		return Alias{}, err
	}

	if err := s.RebuildTable(ctx); err != nil {
		return Alias{}, err
	}

	s.Log.Info("rolled back",
		"alias", name, "release", alias.Release, "from", current.Release, "by", by)
	s.Publish(ctx, AliasChanged(alias, ReasonRollback))

	return alias, nil
}

// RemoveRelease deletes a release and its content.
//
// Refused while any alias points at it. Removing it anyway would leave an
// alias resolving to nothing, and the routes it serves would vanish without
// anyone having asked for that.
func (s *State) RemoveRelease(ctx context.Context, release, by string) error {
	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.unlock()

	stored, err := s.Releases.Get(ctx, release)
	if err != nil {
		return err
	}

	users, err := s.Aliases.ReferencedBy(ctx, release)
	if err != nil {
		return err
	}

	if len(users) > 0 {
		return fmt.Errorf("%w: %s", ErrReleaseInUse, strings.Join(users, ", "))
	}

	// Metadata first, content second - the reverse of publishing, and for the
	// same reason. Once the record is gone the release does not exist, so the
	// content is unreferenced; the other order would leave a release whose
	// routes resolve to missing bytes.
	if err := s.Releases.Remove(ctx, release); err != nil {
		return err
	}

	if err := s.Content.RemoveRelease(ctx, release); err != nil {
		s.Log.Error("removed a release but could not remove its content",
			"release", release, "error", err)
	}

	digests := make([]string, 0, len(stored.Routes))
	for _, route := range stored.Routes {
		digests = append(digests, route.SHA256)
	}

	s.cache.forget(digests)

	if err := s.RebuildTable(ctx); err != nil {
		return err
	}

	s.Log.Info("release removed", "release", release, "by", by)
	s.Publish(ctx, BundleRemoved(release, by))

	return nil
}
