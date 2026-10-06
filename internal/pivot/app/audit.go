package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/adnoctem/netory/pkg/event"
	"github.com/adnoctem/netory/pkg/kv"
	"github.com/adnoctem/netory/pkg/log"
)

// auditPrefix namespaces audit records.
const auditPrefix = "audit/"

// Masks applied by AccessLogAnonymised: a /24 for IPv4 and a /48 for IPv6.
//
// The same masks signpost uses, which are the ones data-protection
// authorities have accepted for analytics anonymisation - the closest thing to
// settled practice. Enough to see where traffic comes from, not enough to
// identify a subscriber.
const (
	anonymiseIPv4Bits = 24
	anonymiseIPv6Bits = 48
)

// AuditKind separates the two things §9.2 asks pivot to record.
type AuditKind string

// The audit kinds.
const (
	// KindAdmin is an administrative action taken through the CLI: a client
	// added, a rule set applied, a token revoked.
	KindAdmin AuditKind = "admin"

	// KindSecurity is a security-relevant request outcome: an authentication
	// failure, a rule denial, a rate-limit refusal, a backend rejection.
	KindSecurity AuditKind = "security"
)

// AuditRecord is one entry in the stored audit trail.
type AuditRecord struct {
	// ID is a sortable identifier; the key is auditPrefix + ID, so a scan
	// yields them in time order once sorted.
	ID string `json:"id"`

	Kind AuditKind `json:"kind"`

	// At is when it happened.
	At time.Time `json:"at"`

	// Actor is who did it: the socket peer for an administrative action, the
	// client id for a request outcome.
	Actor string `json:"actor"`

	// Action names what happened, such as "client.add" or "rule.denied".
	Action string `json:"action"`

	// Subject is what it happened to.
	Subject string `json:"subject,omitempty"`

	// Detail carries the specifics. Bounded and sanitised by the caller: these
	// values reach a log and an operator's screen.
	Detail map[string]string `json:"detail,omitempty"`

	// Replica is which process recorded it, which on a multi-replica
	// deployment is the difference between "this happened" and "this happened
	// here".
	Replica string `json:"replica,omitempty"`
}

// Audit stores the audit trail pivot keeps itself.
//
// # What is stored here and what is not
//
// §9.2 asks for two things, and they have very different volumes. The
// per-request audit log - client, method, normalized path, matched rule,
// status, latency - is one record per request, so it goes to the structured
// log where an operator's log pipeline can handle the volume and the
// retention. What is stored here is the low-volume half: administrative
// actions, and security-relevant outcomes that are already aggregated.
//
// That split is also what makes §10.8's retention promise real. pivot cannot
// enforce a period on records that leave the process, but it can on the ones
// it holds - these carry a kv TTL, so the ninety days is enforced by the store
// rather than asserted in a document.
type Audit struct {
	store     kv.Handle
	logger    *log.Logger
	replica   string
	retention func() time.Duration
	now       func() time.Time
}

// AuditOptions are the dependencies an Audit needs.
type AuditOptions struct {
	Store   kv.Handle
	Logger  *log.Logger
	Replica string

	// Retention is read per write rather than captured, so `config set
	// audit.retention` takes effect without a restart.
	Retention func() time.Duration

	Now func() time.Time
}

// NewAudit returns the audit store.
func NewAudit(opts AuditOptions) (*Audit, error) {
	if opts.Logger == nil {
		return nil, errors.New("app: the audit trail needs a logger")
	}

	if opts.Retention == nil {
		return nil, errors.New("app: the audit trail needs a retention source")
	}

	audit := &Audit{
		store:     opts.Store,
		logger:    opts.Logger,
		replica:   opts.Replica,
		retention: opts.Retention,
		now:       opts.Now,
	}

	if audit.now == nil {
		audit.now = time.Now
	}

	return audit, nil
}

// Record writes an audit entry and logs it.
//
// Both, always. The log is what an operator's pipeline aggregates and alerts
// on; the stored record is what answers "what happened to this customer three
// weeks ago" from any replica without a log search. Writing only one of them
// would lose one of those two uses.
//
// A failure to store is logged and not returned: the action it records has
// already happened, and failing an administrative command because its audit
// write failed would leave the system changed and the operator told it was
// not.
func (a *Audit) Record(ctx context.Context, record AuditRecord) {
	if record.At.IsZero() {
		record.At = a.now().UTC()
	}

	if record.ID == "" {
		record.ID = event.NewID(record.At)
	}

	record.Replica = a.replica

	attrs := []any{
		"kind", string(record.Kind),
		"action", record.Action,
		"actor", record.Actor,
	}

	if record.Subject != "" {
		attrs = append(attrs, "subject", record.Subject)
	}

	for key, value := range record.Detail {
		attrs = append(attrs, key, value)
	}

	a.logger.Info("audit", attrs...)

	retention := a.retention()
	if retention <= 0 {
		// Retention of zero means pivot keeps nothing of its own. The log
		// line above still went out, so the record is not lost - it is simply
		// not pivot's to hold.
		return
	}

	encoded, err := json.Marshal(record)
	if err != nil {
		a.logger.Error("could not encode an audit record", "action", record.Action, "error", err)

		return
	}

	if err := a.store.Set(ctx, auditPrefix+record.ID, encoded, kv.WithTTL(retention)); err != nil {
		a.logger.Error("could not store an audit record",
			"action", record.Action, "error", err)
	}
}

// Admin records an administrative action.
func (a *Audit) Admin(ctx context.Context, actor, action, subject string, detail map[string]string) {
	a.Record(ctx, AuditRecord{
		Kind:    KindAdmin,
		Actor:   actor,
		Action:  action,
		Subject: subject,
		Detail:  detail,
	})
}

// Security records a security-relevant request outcome.
func (a *Audit) Security(ctx context.Context, actor, action, subject string, detail map[string]string) {
	a.Record(ctx, AuditRecord{
		Kind:    KindSecurity,
		Actor:   actor,
		Action:  action,
		Subject: subject,
		Detail:  detail,
	})
}

// List returns the stored records, newest first, at most limit of them.
//
// A namespace walk, which §8.2 says belongs on an administrative path. The
// records are bounded by the retention period rather than by volume, which is
// the other half of why the per-request log is not stored here: ninety days of
// per-request records would make this scan unusable.
func (a *Audit) List(ctx context.Context, kind AuditKind, limit int) ([]AuditRecord, error) {
	var records []AuditRecord

	err := a.store.Scan(ctx, auditPrefix, func(e kv.Entry) error {
		var record AuditRecord
		if err := json.Unmarshal(e.Value, &record); err != nil {
			// One unreadable record must not hide the rest of the trail.
			a.logger.Warn("skipping an undecodable audit record", "key", e.Key, "error", err)

			return nil
		}

		if kind != "" && record.Kind != kind {
			return nil
		}

		records = append(records, record)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("app: list audit records: %w", err)
	}

	// The ids encode time, so sorting them descending is newest first - and
	// it has to be done here, since Scan's order is unspecified.
	sort.Slice(records, func(i, j int) bool { return records[i].ID > records[j].ID })

	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}

	return records, nil
}

// Count returns how many audit records are stored, for `config view`.
func (a *Audit) Count(ctx context.Context) (int, error) {
	keys, err := a.store.Keys(ctx, auditPrefix)
	if err != nil {
		return 0, fmt.Errorf("app: count audit records: %w", err)
	}

	return len(keys), nil
}

// RecordAddress renders a client address for a log or audit record, applying
// the configured mode.
//
// The reduction happens here, before the value reaches a handler, for the same
// reason signpost's does: a record that has left this function carrying a full
// address cannot be un-sent.
func RecordAddress(mode AccessLogAddress, addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}

	addr = addr.Unmap()

	switch mode {
	case AccessLogOff:
		return ""
	case AccessLogAnonymised:
		bits := anonymiseIPv6Bits
		if addr.Is4() {
			bits = anonymiseIPv4Bits
		}

		prefix, err := addr.Prefix(bits)
		if err != nil {
			// Unreachable for a valid address and a fixed bit count. Falling
			// back to empty rather than to the full address keeps a bug here
			// from becoming a privacy incident.
			return ""
		}

		return prefix.String()
	case AccessLogFull:
		return addr.String()
	default:
		// An unrecognised stored value is treated as the safe mode. A settings
		// document from a future version must not make this build record more
		// than it knows it agreed to.
		return ""
	}
}
