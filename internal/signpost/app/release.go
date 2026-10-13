package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/adnoctem/netory/internal/signpost/bundle"
	"github.com/adnoctem/netory/pkg/kv"
)

// releasePrefix namespaces release records.
const releasePrefix = "release/"

// Release is one published bundle.
//
// A release is never modified after publishing. Nothing in this file
// offers a way to change one: the only mutations are create and delete, and
// create refuses an existing name. That is what makes immutability a property
// of the code rather than a convention.
type Release struct {
	// Release is the identifier from the manifest, unique per instance.
	Release string `json:"release"`

	// Description is the manifest's optional note.
	Description string `json:"description,omitempty"`

	// Routes are the published routes, with the digest of each one's content.
	Routes []PublishedRoute `json:"routes"`

	// ArchiveSHA256 is the digest of the archive as published, which is what a
	// signature covered and what the audit record names.
	ArchiveSHA256 string `json:"archive_sha256"`

	// ArchiveSize is the archive's size in bytes.
	ArchiveSize int64 `json:"archive_size"`

	// ManifestName is which manifest filename the bundle carried.
	ManifestName string `json:"manifest_name"`

	// Signature records the verification outcome. The audit trail carries
	// signature status, so it is stored rather than only
	// logged.
	Signature SignatureRecord `json:"signature"`

	// TruncationChecked lists routes that passed the truncation check, and
	// TruncationSkipped those that opted out. Both are recorded because a
	// bundle that skipped the check must stay visible afterwards.
	TruncationChecked []string `json:"truncation_checked,omitempty"`
	TruncationSkipped []string `json:"truncation_skipped,omitempty"`

	// PublishedAt is when it was published, and PublishedBy who by, from the
	// kernel rather than from anything the request claimed.
	PublishedAt time.Time `json:"published_at"`
	PublishedBy string    `json:"published_by"`
}

// SignatureRecord is the signature verification outcome for a release.
type SignatureRecord struct {
	// Verified reports whether a signature was supplied and verified.
	Verified bool `json:"verified"`

	// KeyID identifies the key, as the minisign CLI renders it.
	KeyID string `json:"key_id,omitempty"`

	// TrustedComment is minisign's signed comment, conventionally the
	// filename and a timestamp. It is covered by the global signature, which
	// is why it is worth recording.
	TrustedComment string `json:"trusted_comment,omitempty"`

	// Prehashed records which minisign algorithm was used.
	Prehashed bool `json:"prehashed,omitempty"`
}

// Status renders the signature state for `bundle list`.
func (s SignatureRecord) Status() string {
	if !s.Verified {
		return "unsigned"
	}

	if s.KeyID == "" {
		return "verified"
	}

	return "verified (" + s.KeyID + ")"
}

// PublishedRoute is one route of a published release.
type PublishedRoute struct {
	// Path is the URL path.
	Path string `json:"path"`

	// File is the archive path it came from, kept for diagnostics.
	File string `json:"file"`

	// ContentType is what the route is served as.
	ContentType string `json:"content_type"`

	// SHA256 is the digest of the content, which is both its storage name and
	// its ETag.
	SHA256 string `json:"sha256"`

	// Size is the content's size in bytes.
	Size int64 `json:"size"`
}

// Sentinel errors.
var (
	// ErrReleaseNotFound is returned when a release is not published.
	ErrReleaseNotFound = errors.New("release not found")

	// ErrReleaseExists is returned when publishing a release name that is
	// already taken.
	ErrReleaseExists = errors.New("release already exists")

	// ErrReleaseInUse is returned when removing a release an alias still
	// points at.
	ErrReleaseInUse = errors.New("release is still referenced by an alias")
)

// Releases is the persistence for Release records.
type Releases struct {
	store kv.Handle
}

// NewReleases returns the release repository over a namespace handle.
func NewReleases(store kv.Handle) *Releases { return &Releases{store: store} }

// Create stores a new release, refusing one that already exists.
//
// SetIfAbsent rather than Set, and that is the whole of the "release
// identifiers are unique per instance" guarantee: two publishes racing on the same release name
// cannot both succeed, so a release name can never come to mean two different
// sets of bytes.
func (r *Releases) Create(ctx context.Context, release Release) error {
	if err := bundle.ValidateRelease(release.Release); err != nil {
		return err
	}

	encoded, err := json.Marshal(release)
	if err != nil {
		return fmt.Errorf("encode release %q: %w", release.Release, err)
	}

	wrote, err := r.store.SetIfAbsent(ctx, releasePrefix+release.Release, encoded)
	if err != nil {
		return fmt.Errorf("store release %q: %w", release.Release, err)
	}

	if !wrote {
		return fmt.Errorf("%w: %s", ErrReleaseExists, release.Release)
	}

	return nil
}

// Get returns a release.
func (r *Releases) Get(ctx context.Context, release string) (Release, error) {
	raw, err := r.store.Get(ctx, releasePrefix+release)
	if err != nil {
		if errors.Is(err, kv.ErrNotFound) {
			return Release{}, fmt.Errorf("%w: %s", ErrReleaseNotFound, release)
		}

		return Release{}, fmt.Errorf("read release %q: %w", release, err)
	}

	var stored Release
	if err := json.Unmarshal(raw, &stored); err != nil {
		return Release{}, fmt.Errorf("decode release %q: %w", release, err)
	}

	return stored, nil
}

// Exists reports whether a release is published.
func (r *Releases) Exists(ctx context.Context, release string) (bool, error) {
	has, err := r.store.Has(ctx, releasePrefix+release)
	if err != nil {
		return false, fmt.Errorf("check release %q: %w", release, err)
	}

	return has, nil
}

// List returns every release, newest first.
func (r *Releases) List(ctx context.Context) ([]Release, error) {
	var releases []Release

	err := r.store.Scan(ctx, releasePrefix, func(e kv.Entry) error {
		var stored Release
		if err := json.Unmarshal(e.Value, &stored); err != nil {
			return fmt.Errorf("decode release at %q: %w", e.Key, err)
		}

		releases = append(releases, stored)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list releases: %w", err)
	}

	// kv.Store documents Scan's order as unspecified, so the ordering
	// is applied here rather than inherited from Badger's key order - which
	// the Valkey implementation would not reproduce.
	sort.Slice(releases, func(i, j int) bool {
		if !releases[i].PublishedAt.Equal(releases[j].PublishedAt) {
			return releases[i].PublishedAt.After(releases[j].PublishedAt)
		}

		return releases[i].Release < releases[j].Release
	})

	return releases, nil
}

// Remove deletes a release's metadata.
//
// The caller is responsible for checking no alias references it and for
// removing its stored content; State.RemoveRelease does both in the right
// order.
func (r *Releases) Remove(ctx context.Context, release string) error {
	if _, err := r.Get(ctx, release); err != nil {
		return err
	}

	if err := r.store.Delete(ctx, releasePrefix+release); err != nil {
		return fmt.Errorf("remove release %q: %w", release, err)
	}

	return nil
}

// Route returns one route of a release by path.
func (rel Release) Route(path string) (PublishedRoute, bool) {
	for _, route := range rel.Routes {
		if route.Path == path {
			return route, true
		}
	}

	return PublishedRoute{}, false
}

// Paths returns the release's route paths, sorted.
func (rel Release) Paths() []string {
	paths := make([]string, 0, len(rel.Routes))
	for _, route := range rel.Routes {
		paths = append(paths, route.Path)
	}
	sort.Strings(paths)

	return paths
}
