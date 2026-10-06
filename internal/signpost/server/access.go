package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/adnoctem/netory/internal/signpost/app"
)

// maxLoggedUserAgent bounds what a client can write into the log through its
// User-Agent header.
const maxLoggedUserAgent = 200

// access writes one access-log record.
//
// The record goes to the structured log rather than to the database, and that
// is the resolution of §9.7: a retention period signpost cannot enforce is
// not a promise worth making, because the record leaves this process the
// moment it is written and its lifetime belongs to the operator's log
// pipeline. What signpost does own is how much personal data enters the record
// in the first place, which is the accesslog.client_address setting - data
// minimisation rather than an unenforceable retention claim.
//
// Every field a client controls is bounded and stripped of control characters
// before it is written, because a log line a client can inject a newline into
// is a log line a client can forge.
func (s *Server) access(
	r *http.Request,
	settings app.Settings,
	path string,
	status, bytes int,
	release string,
	started time.Time,
) {
	attrs := []any{
		"method", r.Method,
		"path", sanitise(path, 0),
		"status", status,
		"bytes", bytes,
		"duration", time.Since(started).Round(time.Microsecond).String(),
	}

	if release != "" {
		attrs = append(attrs, "release", release)
	}

	// The address is resolved and then reduced according to the setting. The
	// reduction happens here, before the record is handed to a handler,
	// because a record that has left this function carrying a full address
	// cannot be un-sent.
	if source, err := s.forwarded.Source(r); err == nil {
		if recorded := settings.RecordAddress(source); recorded != "" {
			attrs = append(attrs, "source", recorded)
		}
	}

	if agent := r.UserAgent(); agent != "" {
		attrs = append(attrs, "user_agent", sanitise(agent, maxLoggedUserAgent))
	}

	// Info rather than debug: for a service whose whole job is serving
	// executable content, who fetched what is the record §8.1 asks for, not
	// diagnostic noise.
	s.log.Info("served", attrs...)
}

// sanitise strips control characters from a client-supplied string and bounds
// its length. A limit of zero means no limit.
func sanitise(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}

		return r
	}, value)

	if limit > 0 && len(value) > limit {
		value = value[:limit]
	}

	return value
}
