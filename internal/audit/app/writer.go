// Package app holds the audit trail's use cases.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	auditdomain "github.com/specforge/specforge/internal/audit/domain"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/id"
	"github.com/specforge/specforge/internal/platform/objstore"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/types"
)

// Writer appends audit records inside a caller's transaction.
//
// The signature takes a db.Tx deliberately. For governance-relevant operations
// the audit write must commit with the state change or not at all, so an
// operation that fails to audit cannot succeed.
type Writer interface {
	Append(ctx context.Context, tx db.Tx, r *auditdomain.Record) error
}

// Reader queries the audit trail.
type Reader interface {
	List(ctx context.Context, f Filter) ([]*auditdomain.Record, string, error)
	Get(ctx context.Context, tenantID types.TenantID, sequence int64) (*auditdomain.Record, error)
	Range(ctx context.Context, tenantID types.TenantID, from, to int64) ([]*auditdomain.Record, error)
	Head(ctx context.Context, tenantID types.TenantID) (sequence int64, headHash string, err error)
}

// Filter narrows an audit query.
type Filter struct {
	TenantID  types.TenantID
	ProjectID *types.ProjectID
	Action    string
	Actor     types.PrincipalID
	Outcome   string
	Severity  string
	From      time.Time
	To        time.Time
	Cursor    string
	Limit     int
}

// Service is the audit application service.
type Service struct {
	db       *db.DB
	repo     Repository
	evidence objstore.Store
	bucket   string
}

// Repository is the audit persistence port.
type Repository interface {
	Writer
	Reader
	// NextSequence allocates the next sequence and returns the current chain
	// head, locking the tenant's counter row for the duration of the caller's
	// transaction.
	NextSequence(ctx context.Context, tx db.Tx, tenantID types.TenantID) (sequence int64, prevHash string, err error)
	// AdvanceHead records the new chain head after a successful append.
	AdvanceHead(ctx context.Context, tx db.Tx, tenantID types.TenantID, sequence int64, headHash string) error
	// EnsureChain creates the tenant's chain counter if it does not exist.
	EnsureChain(ctx context.Context, tx db.Tx, tenantID types.TenantID) error
	// SaveAnchor records a published chain head.
	SaveAnchor(ctx context.Context, tx db.Tx, a auditdomain.Anchor) error
	// LatestAnchor returns the most recent anchor for a tenant.
	LatestAnchor(ctx context.Context, tenantID types.TenantID) (*auditdomain.Anchor, error)
}

// NewService builds the audit service.
func NewService(database *db.DB, repo Repository, evidence objstore.Store, bucket string) *Service {
	return &Service{db: database, repo: repo, evidence: evidence, bucket: bucket}
}

// scoped establishes the database tenant session from the tenant the caller
// already named and was authorized for.
//
// Reads in this service take an explicit tenant identifier, so the session is
// derived from that argument rather than from ambient state. Row-level security
// then applies to every statement, which is what makes a mistake here return no
// rows instead of another tenant's history.
func scoped(ctx context.Context, tenantID types.TenantID) context.Context {
	if tc, ok := db.TenantFrom(ctx); ok && tc.TenantID == tenantID {
		return ctx
	}
	return db.WithTenant(ctx, db.TenantContext{TenantID: tenantID})
}

// Append seals and writes a record inside the caller's transaction.
func (s *Service) Append(ctx context.Context, tx db.Tx, r *auditdomain.Record) error {
	const op = "audit.Append"

	if r.ID == "" {
		r.ID = id.NewUUIDv7()
	}
	if r.OccurredAt.IsZero() {
		r.OccurredAt = types.Now()
	}

	seq, prevHash, err := s.repo.NextSequence(ctx, tx, r.TenantID)
	if err != nil {
		return err
	}
	r.Sequence = seq
	r.PrevHash = prevHash

	if err := r.Validate(); err != nil {
		return err
	}
	if err := r.Seal(); err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "audit.seal_failed",
			"Could not compute the audit record hash.")
	}
	if err := s.repo.Append(ctx, tx, r); err != nil {
		return err
	}
	if err := s.repo.AdvanceHead(ctx, tx, r.TenantID, r.Sequence, r.RecordHash); err != nil {
		return err
	}

	obs.Counter("sf_audit_records_total", "Audit records written",
		obs.Labels{"action": r.Action, "outcome": string(r.Outcome)})
	return nil
}

// Verify checks a chain segment and reports the first divergence.
func (s *Service) Verify(ctx context.Context, tenantID types.TenantID, from, to int64) (auditdomain.VerifyReport, error) {
	const op = "audit.Verify"

	if from < 1 {
		from = 1
	}
	ctx = scoped(ctx, tenantID)

	records, err := s.repo.Range(ctx, tenantID, from, to)
	if err != nil {
		return auditdomain.VerifyReport{}, err
	}
	if len(records) == 0 {
		return auditdomain.VerifyReport{TenantID: tenantID, Valid: true}, nil
	}

	// Establish the hash the first record should link to: the genesis value when
	// starting at 1, otherwise the preceding record's stored hash.
	startPrev := hash.ZeroChainHash
	if from > 1 {
		prev, err := s.repo.Get(ctx, tenantID, from-1)
		if err != nil {
			return auditdomain.VerifyReport{}, errors.Wrap(err, op, errors.KindInvalid,
				"audit.range_start_missing",
				"Verification cannot start at sequence %d because the preceding record is missing.", from)
		}
		startPrev = prev.RecordHash
	}

	rep := auditdomain.VerifyChain(records, startPrev)
	result := "valid"
	if !rep.Valid {
		result = "invalid"
	}
	obs.Counter("sf_audit_chain_verifications_total", "Audit chain verification runs",
		obs.Labels{"result": result})
	// A counter of failures is not enough to alert on: it never returns to
	// zero once incremented, so the alert could not clear after remediation.
	// The gauge states the current answer.
	valid := 0.0
	if rep.Valid {
		valid = 1.0
	}
	obs.GaugeSet("sf_audit_chain_valid",
		"1 when the tenant's audit chain last verified successfully, 0 when it did not",
		obs.Labels{"tenant_id": tenantID.String()}, valid)
	return rep, nil
}

// Anchor publishes the current chain head to write-once storage.
//
// This is what makes tampering detectable rather than merely difficult: an
// attacker with full database access can rewrite records, but cannot rewrite an
// anchor that is already under object-lock retention, so the rewrite no longer
// matches the published head.
func (s *Service) Anchor(ctx context.Context, tenantID types.TenantID) (*auditdomain.Anchor, error) {
	const op = "audit.Anchor"

	ctx = scoped(ctx, tenantID)

	seq, head, err := s.repo.Head(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if seq == 0 {
		return nil, nil // nothing to anchor yet
	}

	anchor := auditdomain.Anchor{
		TenantID: tenantID, AnchoredAt: types.Now(),
		Sequence: seq, HeadHash: head,
	}
	body, err := json.Marshal(anchor)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindInternal, "audit.anchor_encode_failed",
			"Could not encode the audit anchor.")
	}

	key := objstore.TenantKey(tenantID, nil,
		fmt.Sprintf("audit-anchors/%s-%d.json", anchor.AnchoredAt.Format("20060102T150405Z"), seq))

	obj, err := s.evidence.PutAt(ctx, s.bucket, key, body, objstore.PutOptions{
		MediaType: "application/vnd.specforge.audit-anchor+json",
		Lock:      true,
		// Anchors outlive the records they cover; a seven year floor matches the
		// default evidence retention.
		RetainUntil: time.Now().AddDate(7, 0, 0),
		Metadata: map[string]string{
			"tenant_id": tenantID.String(),
			"sequence":  fmt.Sprint(seq),
		},
	})
	if err != nil {
		return nil, err
	}
	anchor.StorageRef = obj.Key

	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		return s.repo.SaveAnchor(ctx, tx, anchor)
	})
	if err != nil {
		return nil, err
	}

	obs.Counter("sf_audit_anchors_total", "Audit chain anchors published", nil)
	// The anchor timestamp is published as a gauge so an alert can notice that
	// anchoring has stopped. A chain that is no longer being anchored is still
	// internally consistent and still looks healthy, which is exactly why the
	// absence needs its own signal.
	obs.GaugeSet("sf_audit_last_anchor_timestamp_seconds",
		"Unix time of the most recent published audit anchor",
		obs.Labels{"tenant_id": tenantID.String()},
		float64(anchor.AnchoredAt.Unix()))
	return &anchor, nil
}

// VerifyAgainstAnchor re-verifies the chain from the last anchored position.
//
// This is the check that catches a rewrite of history: verifying the chain in
// isolation only proves internal consistency, and an attacker who rewrites every
// record from a point onward produces an internally consistent chain. Comparing
// against an immutable anchor is what makes that visible.
func (s *Service) VerifyAgainstAnchor(ctx context.Context, tenantID types.TenantID) (auditdomain.VerifyReport, error) {
	ctx = scoped(ctx, tenantID)

	anchor, err := s.repo.LatestAnchor(ctx, tenantID)
	if err != nil {
		return auditdomain.VerifyReport{}, err
	}
	if anchor == nil {
		// No anchor yet: fall back to a full internal verification.
		return s.Verify(ctx, tenantID, 1, 0)
	}

	rec, err := s.repo.Get(ctx, tenantID, anchor.Sequence)
	if err != nil {
		return auditdomain.VerifyReport{
			TenantID: tenantID, Valid: false, FailedAt: anchor.Sequence,
			Reason: "the anchored record is missing from the database",
		}, nil
	}
	if rec.RecordHash != anchor.HeadHash {
		return auditdomain.VerifyReport{
			TenantID: tenantID, Valid: false, FailedAt: anchor.Sequence,
			Reason: "the anchored record's hash no longer matches the published anchor; " +
				"history has been rewritten",
		}, nil
	}

	report, err := s.Verify(ctx, tenantID, 1, 0)
	if err != nil {
		return report, err
	}
	// Recording which anchor the chain was checked against is what separates
	// "internally consistent" from "matches an external reference". An operator
	// reading the report should not have to guess which claim they were given.
	report.AnchoredAt = anchor.Sequence
	return report, nil
}

// List queries the trail.
func (s *Service) List(ctx context.Context, f Filter) ([]*auditdomain.Record, string, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	return s.repo.List(scoped(ctx, f.TenantID), f)
}

// Get returns a single record.
func (s *Service) Get(ctx context.Context, tenantID types.TenantID, seq int64) (*auditdomain.Record, error) {
	return s.repo.Get(scoped(ctx, tenantID), tenantID, seq)
}

// EnsureChain initialises a tenant's audit chain during provisioning.
func (s *Service) EnsureChain(ctx context.Context, tx db.Tx, tenantID types.TenantID) error {
	return s.repo.EnsureChain(ctx, tx, tenantID)
}
