// Package infra implements the audit persistence port against PostgreSQL.
package infra

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	auditapp "github.com/specforge/specforge/internal/audit/app"
	auditdomain "github.com/specforge/specforge/internal/audit/domain"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/types"
)

// Postgres is the audit repository.
type Postgres struct{ db *db.DB }

var _ auditapp.Repository = (*Postgres)(nil)

// NewPostgres builds the repository.
func NewPostgres(database *db.DB) *Postgres { return &Postgres{db: database} }

// EnsureChain creates the tenant's sequence row.
func (p *Postgres) EnsureChain(ctx context.Context, tx db.Tx, tenantID types.TenantID) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_sequences (tenant_id, next_sequence, head_hash)
		VALUES ($1, 1, $2)
		ON CONFLICT (tenant_id) DO NOTHING`, tenantID.String(), hash.ZeroChainHash)
	if err != nil {
		return errors.Wrap(err, "audit.EnsureChain", errors.KindUnavailable,
			"audit.chain_init_failed", "Could not initialise the tenant audit chain.")
	}
	return nil
}

// NextSequence allocates the next sequence number under a row lock.
//
// The lock is what makes the sequence gapless: two concurrent transactions
// serialise here, so neither can skip or reuse a number. Holding it for the
// remainder of the caller's transaction is intentional — audit writes are short,
// and a gapless chain is worth the contention.
func (p *Postgres) NextSequence(ctx context.Context, tx db.Tx, tenantID types.TenantID) (int64, string, error) {
	const op = "audit.NextSequence"

	var (
		seq  int64
		head string
	)
	err := tx.QueryRowContext(ctx, `
		SELECT next_sequence, head_hash FROM audit_sequences
		 WHERE tenant_id = $1 FOR UPDATE`, tenantID.String()).Scan(&seq, &head)

	if db.IsNoRows(err) {
		if _, insErr := tx.ExecContext(ctx, `
			INSERT INTO audit_sequences (tenant_id, next_sequence, head_hash)
			VALUES ($1, 1, $2) ON CONFLICT (tenant_id) DO NOTHING`,
			tenantID.String(), hash.ZeroChainHash); insErr != nil {
			return 0, "", errors.Wrap(insErr, op, errors.KindUnavailable,
				"audit.chain_init_failed", "Could not initialise the tenant audit chain.")
		}
		if err := tx.QueryRowContext(ctx, `
			SELECT next_sequence, head_hash FROM audit_sequences
			 WHERE tenant_id = $1 FOR UPDATE`, tenantID.String()).Scan(&seq, &head); err != nil {
			return 0, "", errors.Wrap(err, op, errors.KindUnavailable,
				"audit.sequence_failed", "Could not allocate an audit sequence.")
		}
	} else if err != nil {
		return 0, "", errors.Wrap(err, op, errors.KindUnavailable,
			"audit.sequence_failed", "Could not allocate an audit sequence.")
	}

	if !hash.ValidChainHash(head) {
		return 0, "", errors.Tampered(op, "audit.chain_head_invalid",
			"The tenant audit chain head is not a valid digest.")
	}
	return seq, head, nil
}

// AdvanceHead moves the chain head forward.
func (p *Postgres) AdvanceHead(ctx context.Context, tx db.Tx, tenantID types.TenantID, seq int64, headHash string) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE audit_sequences
		   SET next_sequence = $2, head_hash = $3, updated_at = now()
		 WHERE tenant_id = $1 AND next_sequence = $4`,
		tenantID.String(), seq+1, headHash, seq)
	if err != nil {
		return errors.Wrap(err, "audit.AdvanceHead", errors.KindUnavailable,
			"audit.chain_advance_failed", "Could not advance the audit chain.")
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		// The counter moved under us, which means the row lock was not held.
		return errors.Conflict("audit.AdvanceHead", "audit.chain_conflict",
			"The audit chain advanced concurrently.")
	}
	return nil
}

const insertSQL = `
INSERT INTO audit_records (
  tenant_id, sequence, id, project_id, action, outcome, severity,
  actor, target, attributes, request_id, trace_id, occurred_at, prev_hash, record_hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10::jsonb,$11,$12,$13,$14,$15)`

// Append writes a sealed record.
func (p *Postgres) Append(ctx context.Context, tx db.Tx, r *auditdomain.Record) error {
	const op = "audit.Append"

	actor, err := json.Marshal(r.Actor)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "audit.encode_failed",
			"Could not encode the audit actor.")
	}
	target, err := json.Marshal(r.Target)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "audit.encode_failed",
			"Could not encode the audit target.")
	}
	attrs, err := json.Marshal(r.Attributes)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "audit.encode_failed",
			"Could not encode the audit attributes.")
	}

	var projectID any
	if r.ProjectID != nil {
		projectID = r.ProjectID.String()
	}

	if _, err := tx.ExecContext(ctx, insertSQL,
		r.TenantID.String(), r.Sequence, r.ID, projectID, r.Action,
		string(r.Outcome), string(r.Severity),
		string(actor), string(target), string(attrs),
		r.RequestID, r.TraceID, r.OccurredAt, r.PrevHash, r.RecordHash); err != nil {

		if db.IsUniqueViolation(err) {
			return errors.Conflict(op, "audit.sequence_conflict",
				"An audit record already exists at this sequence.")
		}
		return errors.Wrap(err, op, errors.KindUnavailable, "audit.append_failed",
			"Could not write the audit record.")
	}
	return nil
}

const selectColumns = `
  tenant_id, sequence, id, project_id, action, outcome, severity,
  actor, target, attributes, request_id, trace_id, occurred_at, prev_hash, record_hash`

func scanRecord(scan func(dest ...any) error) (*auditdomain.Record, error) {
	var (
		r          auditdomain.Record
		tenantID   string
		projectID  *string
		actorRaw   []byte
		targetRaw  []byte
		attrsRaw   []byte
		outcome    string
		severity   string
		occurredAt time.Time
	)
	if err := scan(&tenantID, &r.Sequence, &r.ID, &projectID, &r.Action,
		&outcome, &severity, &actorRaw, &targetRaw, &attrsRaw,
		&r.RequestID, &r.TraceID, &occurredAt, &r.PrevHash, &r.RecordHash); err != nil {
		return nil, err
	}
	r.TenantID = types.TenantID(tenantID)
	if projectID != nil {
		pid := types.ProjectID(*projectID)
		r.ProjectID = &pid
	}
	r.Outcome = auditdomain.Outcome(outcome)
	r.Severity = auditdomain.Severity(severity)
	r.OccurredAt = types.NormalizeTime(occurredAt)

	if err := json.Unmarshal(actorRaw, &r.Actor); err != nil {
		return nil, fmt.Errorf("audit: decoding actor: %w", err)
	}
	if err := json.Unmarshal(targetRaw, &r.Target); err != nil {
		return nil, fmt.Errorf("audit: decoding target: %w", err)
	}
	if err := json.Unmarshal(attrsRaw, &r.Attributes); err != nil {
		return nil, fmt.Errorf("audit: decoding attributes: %w", err)
	}
	return &r, nil
}

// Get returns one record by sequence.
func (p *Postgres) Get(ctx context.Context, tenantID types.TenantID, seq int64) (*auditdomain.Record, error) {
	const op = "audit.Get"

	var rec *auditdomain.Record
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT `+selectColumns+` FROM audit_records WHERE tenant_id = $1 AND sequence = $2`,
			tenantID.String(), seq)
		r, err := scanRecord(row.Scan)
		if db.IsNoRows(err) {
			return errors.NotFound(op, "audit.not_found", "Audit record %d was not found.", seq)
		}
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "audit.read_failed",
				"Could not read the audit record.")
		}
		rec = r
		return nil
	})
	return rec, err
}

// Range returns a contiguous run of records for verification.
func (p *Postgres) Range(ctx context.Context, tenantID types.TenantID, from, to int64) ([]*auditdomain.Record, error) {
	const op = "audit.Range"

	query := `SELECT ` + selectColumns + ` FROM audit_records
	           WHERE tenant_id = $1 AND sequence >= $2`
	args := []any{tenantID.String(), from}
	if to > 0 {
		query += ` AND sequence <= $3`
		args = append(args, to)
	}
	query += ` ORDER BY sequence`

	var out []*auditdomain.Record
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "audit.read_failed",
				"Could not read the audit range.")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			r, err := scanRecord(rows.Scan)
			if err != nil {
				return errors.Wrap(err, op, errors.KindInternal, "audit.decode_failed",
					"Could not decode an audit record.")
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// Head returns the current sequence and chain head.
func (p *Postgres) Head(ctx context.Context, tenantID types.TenantID) (int64, string, error) {
	const op = "audit.Head"

	var (
		next int64
		head string
	)
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		err := tx.QueryRowContext(ctx,
			`SELECT next_sequence, head_hash FROM audit_sequences WHERE tenant_id = $1`,
			tenantID.String()).Scan(&next, &head)
		if db.IsNoRows(err) {
			next, head = 1, hash.ZeroChainHash
			return nil
		}
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "audit.read_failed",
				"Could not read the audit chain head.")
		}
		return nil
	})
	return next - 1, head, err
}

// List queries records with cursor pagination.
//
// The cursor encodes the last sequence seen, which is stable under concurrent
// appends: new records always have higher sequences, so a page never shifts.
func (p *Postgres) List(ctx context.Context, f auditapp.Filter) ([]*auditdomain.Record, string, error) {
	const op = "audit.List"

	var (
		conds = []string{"tenant_id = $1"}
		args  = []any{f.TenantID.String()}
	)
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}

	if f.ProjectID != nil {
		add("project_id = $%d", f.ProjectID.String())
	}
	if f.Action != "" {
		if strings.HasSuffix(f.Action, "*") {
			add("action LIKE $%d", strings.TrimSuffix(f.Action, "*")+"%")
		} else {
			add("action = $%d", f.Action)
		}
	}
	if f.Actor != "" {
		add("actor->>'principal_id' = $%d", f.Actor.String())
	}
	if f.Outcome != "" {
		add("outcome = $%d", f.Outcome)
	}
	if f.Severity != "" {
		add("severity = $%d", f.Severity)
	}
	if !f.From.IsZero() {
		add("occurred_at >= $%d", f.From)
	}
	if !f.To.IsZero() {
		add("occurred_at <= $%d", f.To)
	}
	if f.Cursor != "" {
		seq, err := decodeCursor(f.Cursor)
		if err != nil {
			return nil, "", errors.Invalid(op, "audit.invalid_cursor", "The pagination cursor is not valid.")
		}
		add("sequence < $%d", seq)
	}

	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args = append(args, int64(limit+1))

	query := `SELECT ` + selectColumns + ` FROM audit_records WHERE ` +
		strings.Join(conds, " AND ") +
		fmt.Sprintf(` ORDER BY sequence DESC LIMIT $%d`, len(args))

	var out []*auditdomain.Record
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "audit.read_failed",
				"Could not query the audit trail.")
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			r, err := scanRecord(rows.Scan)
			if err != nil {
				return errors.Wrap(err, op, errors.KindInternal, "audit.decode_failed",
					"Could not decode an audit record.")
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", err
	}

	var next string
	if len(out) > limit {
		out = out[:limit]
		next = encodeCursor(out[len(out)-1].Sequence)
	}
	return out, next, nil
}

// SaveAnchor records a published chain head.
func (p *Postgres) SaveAnchor(ctx context.Context, tx db.Tx, a auditdomain.Anchor) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO audit_anchors (tenant_id, anchored_at, sequence, head_hash, storage_ref)
		VALUES ($1, $2, $3, $4, $5)`,
		a.TenantID.String(), a.AnchoredAt, a.Sequence, a.HeadHash, a.StorageRef)
	if err != nil {
		return errors.Wrap(err, "audit.SaveAnchor", errors.KindUnavailable,
			"audit.anchor_failed", "Could not record the audit anchor.")
	}
	return nil
}

// LatestAnchor returns the most recent anchor.
func (p *Postgres) LatestAnchor(ctx context.Context, tenantID types.TenantID) (*auditdomain.Anchor, error) {
	var a auditdomain.Anchor
	var tid string
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		err := tx.QueryRowContext(ctx, `
			SELECT tenant_id, anchored_at, sequence, head_hash, storage_ref
			  FROM audit_anchors WHERE tenant_id = $1
			 ORDER BY anchored_at DESC LIMIT 1`, tenantID.String()).
			Scan(&tid, &a.AnchoredAt, &a.Sequence, &a.HeadHash, &a.StorageRef)
		if db.IsNoRows(err) {
			return nil
		}
		return err
	})
	if err != nil {
		return nil, errors.Wrap(err, "audit.LatestAnchor", errors.KindUnavailable,
			"audit.read_failed", "Could not read the audit anchor.")
	}
	if tid == "" {
		return nil, nil
	}
	a.TenantID = types.TenantID(tid)
	return &a, nil
}

func encodeCursor(seq int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("s" + strconv.FormatInt(seq, 10)))
}

func decodeCursor(c string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil || len(raw) < 2 || raw[0] != 's' {
		return 0, fmt.Errorf("audit: malformed cursor")
	}
	return strconv.ParseInt(string(raw[1:]), 10, 64)
}
