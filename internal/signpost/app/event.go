package app

import (
	"strconv"
	"strings"

	"github.com/adnoctem/netory/pkg/event"
)

// signpost's event taxonomy, as §7.2 defines it.
//
// Four events, all of them about the integrity of what is being served. There
// is deliberately no event for a served request: signpost serves anonymously
// and at whatever rate the internet brings, so an event per request would be a
// denial-of-service amplifier pointed at the operator's mailbox.
const (
	// EventBundlePublished fires when a new release is created.
	EventBundlePublished = event.Type("bundle.published")

	// EventBundleRejected fires when validation failed on publish.
	//
	// Worth notifying on rather than only logging: a rejected publish is
	// either a broken bundle or an attempt to publish something malformed,
	// and both are things an operator wants to hear about at the time.
	EventBundleRejected = event.Type("bundle.rejected")

	// EventAliasChanged fires when an alias moves, including rollbacks.
	EventAliasChanged = event.Type("alias.changed")

	// EventBundleRemoved fires when a release is deleted.
	EventBundleRemoved = event.Type("bundle.removed")
)

// EventTypes lists every event signpost emits, for `notifier` documentation
// and for the test that asserts the taxonomy matches the design document.
func EventTypes() []event.Type {
	return []event.Type{
		EventBundlePublished,
		EventBundleRejected,
		EventAliasChanged,
		EventBundleRemoved,
	}
}

// BundlePublished builds the event for a new release.
//
// The archive digest and the signature status are both carried, because §8.1
// requires the audit trail to name them and a notification an operator reads
// is the most likely place that record is actually looked at.
func BundlePublished(release Release) event.Event {
	e := event.New(EventBundlePublished, release.Release, "a new release was published").
		WithField("by", release.PublishedBy).
		WithField("archive_sha256", release.ArchiveSHA256).
		WithField("routes", strconv.Itoa(len(release.Routes))).
		WithField("signature", release.Signature.Status())

	if len(release.TruncationSkipped) > 0 {
		// Surfaced in the notification rather than only stored: a route that
		// opted out of the §6.3 check is the one route in the bundle whose
		// partial delivery could execute, and that is worth saying out loud
		// at the moment it is published.
		e = e.WithField("truncation_check_skipped", strings.Join(release.TruncationSkipped, " "))
	}

	return e
}

// BundleRejected builds the event for a bundle that failed validation.
//
// The subject is the release the bundle claimed, or "unknown" when it was
// rejected before a manifest could be read - which is itself informative,
// since it means the archive never parsed.
func BundleRejected(release, by string, cause error) event.Event {
	if release == "" {
		release = "unknown"
	}

	e := event.New(EventBundleRejected, release, "a bundle was rejected on publish").
		WithField("by", by)

	if cause != nil {
		e = e.WithField("error", cause.Error())
	}

	return e
}

// AliasChanged builds the event for an alias moving.
//
// reason distinguishes a publish from a rollback from a manual `alias set`,
// because the three have very different implications for whoever reads the
// notification: one is expected, one means something broke, and one means a
// person moved a pointer by hand.
func AliasChanged(alias Alias, reason string) event.Event {
	e := event.New(EventAliasChanged, alias.Name, "an alias was moved").
		WithField("release", alias.Release).
		WithField("by", alias.UpdatedBy).
		WithField("reason", reason)

	if alias.Previous != "" {
		e = e.WithField("previous", alias.Previous)
	}

	return e
}

// BundleRemoved builds the event for a deleted release.
func BundleRemoved(release, by string) event.Event {
	return event.New(EventBundleRemoved, release, "a release was removed").
		WithField("by", by)
}
