// Package domain holds the audit trail's entities and invariants.
//
// The audit trail is the platform's memory. Its value comes entirely from being
// complete and tamper-evident, so two rules hold without exception:
//
//   - Records are append-only. A correction is a new record, never an edit.
//   - Each record's hash covers the previous record's hash, so altering any
//     record invalidates every record after it.
package domain

import (
	"fmt"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/types"
)

// Outcome is the result of an audited operation.
type Outcome string

const (
	OutcomeSuccess Outcome = "SUCCESS"
	OutcomeDenied  Outcome = "DENIED"
	OutcomeFailure Outcome = "FAILURE"
)

func (o Outcome) Valid() bool {
	switch o {
	case OutcomeSuccess, OutcomeDenied, OutcomeFailure:
		return true
	}
	return false
}

// Severity grades an audit record for alerting and retention.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityNotice   Severity = "NOTICE"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityNotice, SeverityWarning, SeverityCritical:
		return true
	}
	return false
}

// Actor identifies who performed an operation.
type Actor struct {
	Kind        string            `json:"kind"` // USER | SERVICE_ACCOUNT | SYSTEM
	PrincipalID types.PrincipalID `json:"principal_id,omitempty"`
	Display     string            `json:"display,omitempty"`
	Subject     string            `json:"subject,omitempty"`
	Issuer      string            `json:"issuer,omitempty"`
	// OnBehalfOf records the originating user when a system principal acts for
	// them, so delegated actions remain attributable to a human.
	OnBehalfOf types.PrincipalID `json:"on_behalf_of,omitempty"`
	BreakGlass bool              `json:"break_glass,omitempty"`
	// IPHash is a salted hash rather than the address itself, so the trail
	// supports anomaly detection without storing a direct personal identifier.
	IPHash    string `json:"ip_hash,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// Target identifies what was operated on.
type Target struct {
	Type      string `json:"type"`
	ID        string `json:"id,omitempty"`
	Version   int    `json:"version,omitempty"`
	ProjectID string `json:"project_id,omitempty"`
	// ContentHash pins the exact artifact state involved, so an auditor can
	// verify the record refers to the bytes they are looking at.
	ContentHash string `json:"content_hash,omitempty"`
}

// Record is one immutable audit entry.
type Record struct {
	ID         string
	TenantID   types.TenantID
	ProjectID  *types.ProjectID
	Sequence   int64
	Action     string
	Outcome    Outcome
	Severity   Severity
	Actor      Actor
	Target     Target
	Attributes map[string]any
	RequestID  string
	TraceID    string
	OccurredAt time.Time
	PrevHash   string
	RecordHash string
}

// chainPayload is the canonical projection that the chain hash covers.
//
// RecordHash is excluded because it is the output. Everything else is included:
// omitting a field would let it be changed without breaking the chain.
type chainPayload struct {
	ID         string         `json:"id"`
	TenantID   string         `json:"tenant_id"`
	ProjectID  string         `json:"project_id,omitempty"`
	Sequence   int64          `json:"sequence"`
	Action     string         `json:"action"`
	Outcome    string         `json:"outcome"`
	Severity   string         `json:"severity"`
	Actor      Actor          `json:"actor"`
	Target     Target         `json:"target"`
	Attributes map[string]any `json:"attributes"`
	RequestID  string         `json:"request_id,omitempty"`
	TraceID    string         `json:"trace_id,omitempty"`
	OccurredAt string         `json:"occurred_at"`
	PrevHash   string         `json:"prev_hash"`
}

// Payload returns the canonical hashing projection.
func (r *Record) Payload() chainPayload {
	projectID := ""
	if r.ProjectID != nil {
		projectID = r.ProjectID.String()
	}
	attrs := r.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	return chainPayload{
		ID: r.ID, TenantID: r.TenantID.String(), ProjectID: projectID,
		Sequence: r.Sequence, Action: r.Action,
		Outcome: string(r.Outcome), Severity: string(r.Severity),
		Actor: r.Actor, Target: r.Target, Attributes: attrs,
		RequestID: r.RequestID, TraceID: r.TraceID,
		// RFC 3339 with nanoseconds in UTC: a stable rendering is required or the
		// hash would depend on the local timezone of whoever recomputes it.
		OccurredAt: types.NormalizeTime(r.OccurredAt).Format(time.RFC3339Nano),
		PrevHash:   r.PrevHash,
	}
}

// ComputeHash derives the record hash from the previous chain head.
func (r *Record) ComputeHash() (string, error) {
	if !hash.ValidChainHash(r.PrevHash) {
		return "", errors.Invalid("audit.ComputeHash", "audit.invalid_prev_hash",
			"The previous chain hash is not a 64-character hex digest.")
	}
	return hash.ChainOf(r.PrevHash, r.Payload())
}

// Seal computes and sets the record hash.
func (r *Record) Seal() error {
	h, err := r.ComputeHash()
	if err != nil {
		return err
	}
	r.RecordHash = h
	return nil
}

// VerifyHash recomputes the hash and compares it with the stored value.
func (r *Record) VerifyHash() (bool, error) {
	h, err := r.ComputeHash()
	if err != nil {
		return false, err
	}
	return h == r.RecordHash, nil
}

// Validate enforces the record's invariants before it is written.
func (r *Record) Validate() error {
	const op = "audit.Validate"

	if r.TenantID.Empty() {
		return errors.Invalid(op, "audit.tenant_required", "An audit record must name a tenant.")
	}
	if strings.TrimSpace(r.Action) == "" {
		return errors.Invalid(op, "audit.action_required", "An audit record must name an action.")
	}
	if !strings.Contains(r.Action, ".") {
		return errors.Invalid(op, "audit.action_malformed",
			"Audit action %q must be of the form <domain>.<verb>.", r.Action)
	}
	if !r.Outcome.Valid() {
		return errors.Invalid(op, "audit.outcome_invalid", "Outcome %q is not recognised.", r.Outcome)
	}
	if !r.Severity.Valid() {
		return errors.Invalid(op, "audit.severity_invalid", "Severity %q is not recognised.", r.Severity)
	}
	if r.Actor.Kind == "" {
		return errors.Invalid(op, "audit.actor_required", "An audit record must name an actor.")
	}
	if r.Target.Type == "" {
		return errors.Invalid(op, "audit.target_required", "An audit record must name a target.")
	}
	if r.Sequence < 1 {
		return errors.Invalid(op, "audit.sequence_invalid", "Audit sequences start at 1.")
	}
	if r.OccurredAt.IsZero() {
		return errors.Invalid(op, "audit.timestamp_required", "An audit record must be timestamped.")
	}
	return nil
}

// New builds an unsealed record. The caller supplies the sequence and previous
// hash from the tenant's chain, both allocated under a row lock.
func New(
	tenantID types.TenantID,
	projectID *types.ProjectID,
	action string,
	outcome Outcome,
	severity Severity,
	actor Actor,
	target Target,
) *Record {
	return &Record{
		TenantID: tenantID, ProjectID: projectID, Action: action,
		Outcome: outcome, Severity: severity, Actor: actor, Target: target,
		Attributes: map[string]any{}, OccurredAt: types.Now(),
	}
}

// WithAttr attaches a structured attribute.
//
// Attributes must already be redacted. The audit trail is queried by people who
// are not the data's owner, so raw content and credentials never belong here —
// reference content by hash instead.
func (r *Record) WithAttr(k string, v any) *Record {
	if r.Attributes == nil {
		r.Attributes = map[string]any{}
	}
	r.Attributes[k] = v
	return r
}

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

// VerifyReport is the result of verifying a chain segment.
type VerifyReport struct {
	TenantID       types.TenantID `json:"tenant_id"`
	From           int64          `json:"from"`
	To             int64          `json:"to"`
	RecordsChecked int64          `json:"records_checked"`
	Valid          bool           `json:"valid"`
	// FailedAt is the first sequence whose hash or linkage is wrong.
	FailedAt int64  `json:"failed_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// GapAt is the first missing sequence number, if the chain is not contiguous.
	GapAt int64 `json:"gap_at,omitempty"`
	// AnchoredAt is the sequence of the anchor the chain was compared against,
	// when the check included one. Zero means the chain was only checked for
	// internal consistency, which is a strictly weaker claim.
	AnchoredAt int64 `json:"anchored_at,omitempty"`
}

// VerifyChain checks a contiguous run of records.
//
// Three things are verified, and all three matter: each record's own hash, the
// linkage from one record to the next, and the absence of gaps. Checking only
// the hashes would miss a wholesale deletion of a contiguous block.
func VerifyChain(records []*Record, startPrevHash string) VerifyReport {
	rep := VerifyReport{Valid: true}
	if len(records) == 0 {
		return rep
	}
	rep.TenantID = records[0].TenantID
	rep.From = records[0].Sequence
	rep.To = records[len(records)-1].Sequence

	prev := startPrevHash
	expected := records[0].Sequence

	for _, rec := range records {
		rep.RecordsChecked++

		if rec.Sequence != expected {
			rep.Valid = false
			rep.GapAt = expected
			rep.FailedAt = rec.Sequence
			rep.Reason = fmt.Sprintf(
				"the chain is not contiguous: expected sequence %d, found %d", expected, rec.Sequence)
			return rep
		}
		if rec.PrevHash != prev {
			rep.Valid = false
			rep.FailedAt = rec.Sequence
			rep.Reason = fmt.Sprintf(
				"record %d does not link to its predecessor", rec.Sequence)
			return rep
		}
		ok, err := rec.VerifyHash()
		if err != nil {
			rep.Valid = false
			rep.FailedAt = rec.Sequence
			rep.Reason = fmt.Sprintf("record %d could not be hashed: %v", rec.Sequence, err)
			return rep
		}
		if !ok {
			rep.Valid = false
			rep.FailedAt = rec.Sequence
			rep.Reason = fmt.Sprintf(
				"record %d has been altered since it was written", rec.Sequence)
			return rep
		}

		prev = rec.RecordHash
		expected++
	}
	return rep
}

// Anchor is a periodically published chain head, written to write-once storage
// so that tampering remains detectable even to an attacker with full database
// access.
type Anchor struct {
	TenantID   types.TenantID `json:"tenant_id"`
	AnchoredAt time.Time      `json:"anchored_at"`
	Sequence   int64          `json:"sequence"`
	HeadHash   string         `json:"head_hash"`
	StorageRef string         `json:"storage_ref"`
}
