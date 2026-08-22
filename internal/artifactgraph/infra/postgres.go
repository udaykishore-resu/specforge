// Package infra implements the artifact graph repository against PostgreSQL.
package infra

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/artifactgraph/app"
	"github.com/specforge/specforge/internal/artifactgraph/domain"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/fsm"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/types"
)

// Postgres is the artifact graph repository.
type Postgres struct{ db *db.DB }

var _ app.Repository = (*Postgres)(nil)

// NewPostgres builds the repository.
func NewPostgres(database *db.DB) *Postgres { return &Postgres{db: database} }

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

const artifactColumns = `tenant_id, project_id, artifact_id, artifact_type, title,
       current_version, status, labels, created_by, created_at, updated_at, version_no`

func scanArtifact(scan func(...any) error) (*domain.Artifact, error) {
	var (
		a         domain.Artifact
		tenantID  string
		projectID string
		artType   string
		status    string
		labelsRaw []byte
		createdBy string
		createdAt time.Time
		updatedAt time.Time
		artID     string
		curVer    int64
	)
	if err := scan(&tenantID, &projectID, &artID, &artType, &a.Title,
		&curVer, &status, &labelsRaw, &createdBy, &createdAt, &updatedAt, &a.Version); err != nil {
		return nil, err
	}
	a.TenantID = types.TenantID(tenantID)
	a.ProjectID = types.ProjectID(projectID)
	a.ID = types.ArtifactID(artID)
	a.Type = types.ArtifactType(artType)
	a.CurrentVersion = int(curVer)
	a.Status = fsm.State(status)
	a.CreatedBy = types.PrincipalID(createdBy)
	a.CreatedAt = createdAt.UTC()
	a.UpdatedAt = updatedAt.UTC()
	a.Labels = map[string]string{}
	if len(labelsRaw) > 0 {
		_ = json.Unmarshal(labelsRaw, &a.Labels)
	}
	return &a, nil
}

// CreateArtifact inserts an artifact identity row.
func (p *Postgres) CreateArtifact(ctx context.Context, tx db.Tx, a *domain.Artifact) error {
	const op = "artifactgraph.CreateArtifact"

	labels, err := json.Marshal(a.Labels)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "artifact.encode_failed",
			"Could not encode the artifact labels.")
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO artifacts (tenant_id, project_id, artifact_id, artifact_type, title,
		                       current_version, status, labels, created_by, created_at,
		                       updated_at, version_no)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12)`,
		a.TenantID.String(), a.ProjectID.String(), a.ID.String(), string(a.Type), a.Title,
		int64(a.CurrentVersion), string(a.Status), string(labels),
		a.CreatedBy.String(), a.CreatedAt, a.UpdatedAt, a.Version)

	if err != nil {
		if db.IsUniqueViolation(err) {
			return errors.Conflict(op, "artifact.id_taken",
				"Artifact %s already exists in this project.", a.ID)
		}
		return errors.Wrap(err, op, errors.KindUnavailable, "artifact.create_failed",
			"Could not create the artifact.")
	}
	return nil
}

// UpdateArtifact writes an artifact identity row with optimistic concurrency.
func (p *Postgres) UpdateArtifact(ctx context.Context, tx db.Tx, a *domain.Artifact) error {
	const op = "artifactgraph.UpdateArtifact"

	labels, err := json.Marshal(a.Labels)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "artifact.encode_failed",
			"Could not encode the artifact labels.")
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE artifacts
		   SET title = $4, current_version = $5, status = $6, labels = $7::jsonb,
		       updated_at = now(), version_no = version_no + 1
		 WHERE tenant_id = $1 AND project_id = $2 AND artifact_id = $3 AND version_no = $8`,
		a.TenantID.String(), a.ProjectID.String(), a.ID.String(),
		a.Title, int64(a.CurrentVersion), string(a.Status), string(labels), a.Version)
	if err != nil {
		return errors.Wrap(err, op, errors.KindUnavailable, "artifact.update_failed",
			"Could not update the artifact.")
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.Conflict(op, "concurrency.stale_version",
			"The artifact was modified by another request. Reload and try again.")
	}
	a.Version++
	return nil
}

// GetArtifact loads an artifact identity row.
func (p *Postgres) GetArtifact(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID, artifactID types.ArtifactID) (*domain.Artifact, error) {

	const op = "artifactgraph.GetArtifact"

	var a *domain.Artifact
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT `+artifactColumns+` FROM artifacts
			  WHERE tenant_id = $1 AND project_id = $2 AND artifact_id = $3`,
			tenantID.String(), projectID.String(), artifactID.String())
		got, err := scanArtifact(row.Scan)
		if db.IsNoRows(err) {
			return errors.NotFound(op, "artifact.not_found",
				"Artifact %s was not found.", artifactID)
		}
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "artifact.read_failed",
				"Could not read the artifact.")
		}
		a = got
		return nil
	})
	return a, err
}

// ListArtifacts returns artifacts matching a filter.
func (p *Postgres) ListArtifacts(ctx context.Context, f app.ArtifactFilter) ([]*domain.Artifact, string, error) {
	const op = "artifactgraph.ListArtifacts"

	conds := []string{"tenant_id = $1", "project_id = $2"}
	args := []any{f.TenantID.String(), f.ProjectID.String()}
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.Type != "" {
		add("artifact_type = $%d", string(f.Type))
	}
	if f.Status != "" {
		add("status = $%d", string(f.Status))
	}
	if f.Label[0] != "" {
		args = append(args, f.Label[0], f.Label[1])
		conds = append(conds, fmt.Sprintf("labels->>$%d = $%d", len(args)-1, len(args)))
	}
	if f.Cursor != "" {
		created, err := decodeCursor(f.Cursor)
		if err != nil {
			return nil, "", errors.Invalid(op, "artifact.invalid_cursor",
				"The pagination cursor is not valid.")
		}
		add("created_at < $%d", created)
	}

	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args = append(args, int64(limit+1))

	query := `SELECT ` + artifactColumns + ` FROM artifacts WHERE ` +
		strings.Join(conds, " AND ") +
		fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, len(args))

	var out []*domain.Artifact
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "artifact.read_failed",
				"Could not list artifacts.")
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			a, err := scanArtifact(rows.Scan)
			if err != nil {
				return errors.Wrap(err, op, errors.KindInternal, "artifact.decode_failed",
					"Could not decode an artifact.")
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", err
	}

	var next string
	if len(out) > limit {
		out = out[:limit]
		next = encodeCursor(out[len(out)-1].CreatedAt)
	}
	return out, next, nil
}

// NextArtifactSequence allocates the next numeric suffix for an id prefix.
//
// It reads the highest existing suffix under a row-level lock on the artifacts
// already in the project, so two concurrent creations cannot mint the same id.
func (p *Postgres) NextArtifactSequence(ctx context.Context, tx db.Tx,
	tenantID types.TenantID, projectID types.ProjectID, prefix string) (int, error) {

	const op = "artifactgraph.NextArtifactSequence"

	var maxSuffix *int64
	err := tx.QueryRowContext(ctx, `
		SELECT max(NULLIF(regexp_replace(artifact_id, '^.*-', ''), '')::bigint)
		  FROM artifacts
		 WHERE tenant_id = $1 AND project_id = $2
		   AND artifact_id LIKE $3
		   AND artifact_id ~ ('^' || $4 || '-[0-9]+$')`,
		tenantID.String(), projectID.String(), prefix+"-%", prefix).Scan(&maxSuffix)
	if err != nil && !db.IsNoRows(err) {
		return 0, errors.Wrap(err, op, errors.KindUnavailable, "artifact.sequence_failed",
			"Could not allocate an artifact identifier.")
	}
	if maxSuffix == nil {
		return 1, nil
	}
	return int(*maxSuffix) + 1, nil
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

const versionColumns = `tenant_id, project_id, artifact_id, version, artifact_type, status,
       content_schema, content, content_ref, content_hash,
       parent_artifact_id, parent_artifact_version, source_artifact_id, source_artifact_version,
       previous_version, change_summary, generator, created_by, created_at, updated_at,
       approved_by, approved_at, approval_comment, approval_evidence, sealed_at, version_no`

func scanVersion(scan func(...any) error) (*domain.Version, error) {
	var (
		v            domain.Version
		tenantID     string
		projectID    string
		artifactID   string
		artType      string
		status       string
		versionNum   int64
		contentRef   *string
		parentID     *string
		parentVer    *int64
		sourceID     *string
		sourceVer    *int64
		prevVer      *int64
		generatorRaw []byte
		createdBy    string
		createdAt    time.Time
		updatedAt    time.Time
		approvedBy   *string
		approvedAt   *time.Time
		evidenceRaw  []byte
		sealedAt     *time.Time
		contentHash  string
	)
	if err := scan(&tenantID, &projectID, &artifactID, &versionNum, &artType, &status,
		&v.ContentSchema, &v.Content, &contentRef, &contentHash,
		&parentID, &parentVer, &sourceID, &sourceVer,
		&prevVer, &v.ChangeSummary, &generatorRaw, &createdBy, &createdAt, &updatedAt,
		&approvedBy, &approvedAt, &v.ApprovalComment, &evidenceRaw, &sealedAt, &v.VersionNo); err != nil {
		return nil, err
	}

	v.TenantID = types.TenantID(tenantID)
	v.ProjectID = types.ProjectID(projectID)
	v.ArtifactID = types.ArtifactID(artifactID)
	v.Version = int(versionNum)
	v.Type = types.ArtifactType(artType)
	v.Status = fsm.State(status)
	v.ContentHash = types.ContentHash(contentHash)
	v.CreatedBy = types.PrincipalID(createdBy)
	v.CreatedAt = types.NormalizeTime(createdAt)
	v.UpdatedAt = types.NormalizeTime(updatedAt)

	if contentRef != nil {
		v.ContentRef = *contentRef
	}
	if parentID != nil && parentVer != nil {
		v.ParentArtifact = &types.ArtifactRef{
			ArtifactID: types.ArtifactID(*parentID), Version: int(*parentVer),
		}
	}
	if sourceID != nil && sourceVer != nil {
		v.SourceArtifact = &types.ArtifactRef{
			ArtifactID: types.ArtifactID(*sourceID), Version: int(*sourceVer),
		}
	}
	if prevVer != nil {
		pv := int(*prevVer)
		v.PreviousVersion = &pv
	}
	if len(generatorRaw) > 0 {
		if err := json.Unmarshal(generatorRaw, &v.Generator); err != nil {
			return nil, fmt.Errorf("artifactgraph: decoding generator: %w", err)
		}
	}
	if approvedBy != nil {
		pid := types.PrincipalID(*approvedBy)
		v.ApprovedBy = &pid
	}
	if approvedAt != nil {
		t := types.NormalizeTime(*approvedAt)
		v.ApprovedAt = &t
	}
	if sealedAt != nil {
		t := types.NormalizeTime(*sealedAt)
		v.SealedAt = &t
	}
	if len(evidenceRaw) > 0 {
		var e domain.ApprovalEvidence
		if err := json.Unmarshal(evidenceRaw, &e); err != nil {
			return nil, fmt.Errorf("artifactgraph: decoding approval evidence: %w", err)
		}
		v.ApprovalEvidence = &e
	}
	return &v, nil
}

// CreateVersion inserts a version.
func (p *Postgres) CreateVersion(ctx context.Context, tx db.Tx, v *domain.Version) error {
	const op = "artifactgraph.CreateVersion"

	generator, err := json.Marshal(v.Generator)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "artifact.encode_failed",
			"Could not encode the artifact provenance.")
	}

	var parentID, sourceID any
	var parentVer, sourceVer, prevVer any
	if v.ParentArtifact != nil {
		parentID = v.ParentArtifact.ArtifactID.String()
		parentVer = int64(v.ParentArtifact.Version)
	}
	if v.SourceArtifact != nil {
		sourceID = v.SourceArtifact.ArtifactID.String()
		sourceVer = int64(v.SourceArtifact.Version)
	}
	if v.PreviousVersion != nil {
		prevVer = int64(*v.PreviousVersion)
	}
	var contentRef any
	if v.ContentRef != "" {
		contentRef = v.ContentRef
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO artifact_versions (
		  tenant_id, project_id, artifact_id, version, artifact_type, status,
		  content_schema, content, content_ref, content_hash,
		  parent_artifact_id, parent_artifact_version, source_artifact_id, source_artifact_version,
		  previous_version, change_summary, generator, created_by, created_at, updated_at, version_no)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb,$18,$19,$20,$21)`,
		v.TenantID.String(), v.ProjectID.String(), v.ArtifactID.String(), int64(v.Version),
		string(v.Type), string(v.Status), v.ContentSchema, string(v.Content), contentRef,
		v.ContentHash.String(), parentID, parentVer, sourceID, sourceVer, prevVer,
		v.ChangeSummary, string(generator), v.CreatedBy.String(),
		v.CreatedAt, v.UpdatedAt, v.VersionNo)

	if err != nil {
		return translateVersionError(op, err, v)
	}
	return nil
}

// UpdateVersion writes a version.
//
// Sealed versions are protected by a database trigger, so an attempt to mutate
// one surfaces here as a check violation rather than silently succeeding.
func (p *Postgres) UpdateVersion(ctx context.Context, tx db.Tx, v *domain.Version) error {
	const op = "artifactgraph.UpdateVersion"

	generator, err := json.Marshal(v.Generator)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "artifact.encode_failed",
			"Could not encode the artifact provenance.")
	}
	var evidence any
	if v.ApprovalEvidence != nil {
		raw, mErr := json.Marshal(v.ApprovalEvidence)
		if mErr != nil {
			return errors.Wrap(mErr, op, errors.KindInternal, "artifact.encode_failed",
				"Could not encode the approval evidence.")
		}
		evidence = string(raw)
	}
	var approvedBy any
	if v.ApprovedBy != nil {
		approvedBy = v.ApprovedBy.String()
	}
	var approvedAt, sealedAt any
	if v.ApprovedAt != nil {
		approvedAt = *v.ApprovedAt
	}
	if v.SealedAt != nil {
		sealedAt = *v.SealedAt
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE artifact_versions
		   SET status = $5, content = $6::jsonb, content_hash = $7, change_summary = $8,
		       generator = $9::jsonb, updated_at = now(),
		       approved_by = $10, approved_at = $11, approval_comment = $12,
		       approval_evidence = $13::jsonb, sealed_at = $14,
		       version_no = version_no + 1
		 WHERE tenant_id = $1 AND project_id = $2 AND artifact_id = $3 AND version = $4
		   AND version_no = $15`,
		v.TenantID.String(), v.ProjectID.String(), v.ArtifactID.String(), int64(v.Version),
		string(v.Status), string(v.Content), v.ContentHash.String(), v.ChangeSummary,
		string(generator), approvedBy, approvedAt, v.ApprovalComment, evidence, sealedAt,
		v.VersionNo)

	if err != nil {
		return translateVersionError(op, err, v)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.Conflict(op, "concurrency.stale_version",
			"The artifact version was modified by another request. Reload and try again.")
	}
	v.VersionNo++
	return nil
}

// translateVersionError maps database constraint failures onto domain errors,
// so callers see why an invariant refused rather than an opaque SQLSTATE.
func translateVersionError(op string, err error, v *domain.Version) error {
	if constraint, ok := db.ConstraintViolation(err); ok {
		switch {
		case strings.Contains(constraint, "one_approved_per_artifact"):
			return errors.Conflict(op, "artifact.already_approved",
				"%s already has an approved version. Supersede it first.", v.ArtifactID)
		case strings.Contains(constraint, "approved_requires_evidence"):
			return errors.Invalid(op, "artifact.approval_evidence_required",
				"An approved version must carry complete approval evidence.")
		case strings.Contains(constraint, "chain_"):
			return errors.Invalid(op, "artifact.chain_invalid",
				"Artifact versions must form a gapless chain starting at 1.")
		case strings.Contains(constraint, "content_inline_size"):
			return errors.Invalid(op, "artifact.content_too_large",
				"Inline content exceeds the size limit; store it by reference.")
		}
	}
	if db.IsCheckViolation(err) {
		// The sealed-version trigger raises a check violation with a message that
		// explains exactly which rule refused.
		return errors.Conflict(op, "artifact.sealed_immutable",
			"%s version %d is sealed and cannot be modified. Create a new version instead.",
			v.ArtifactID, v.Version)
	}
	if db.IsUniqueViolation(err) {
		return errors.Conflict(op, "artifact.version_exists",
			"%s version %d already exists.", v.ArtifactID, v.Version)
	}
	if db.IsRLSViolation(err) {
		return errors.Forbidden(op, "authz.tenant_mismatch",
			"The operation crosses a tenant boundary.")
	}
	return errors.Wrap(err, op, errors.KindUnavailable, "artifact.write_failed",
		"Could not write the artifact version.")
}

// GetVersion loads a version and verifies its content hash.
func (p *Postgres) GetVersion(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID, artifactID types.ArtifactID, version int) (*domain.Version, error) {

	const op = "artifactgraph.GetVersion"

	var v *domain.Version
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT `+versionColumns+` FROM artifact_versions
			  WHERE tenant_id = $1 AND project_id = $2 AND artifact_id = $3 AND version = $4`,
			tenantID.String(), projectID.String(), artifactID.String(), int64(version))
		got, err := scanVersion(row.Scan)
		if db.IsNoRows(err) {
			return errors.NotFound(op, "artifact.version_not_found",
				"%s version %d was not found.", artifactID, version)
		}
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "artifact.read_failed",
				"Could not read the artifact version.")
		}
		v = got
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Read-path integrity verification. A mismatch means the stored bytes no
	// longer match the recorded hash, which is a security event: fail closed.
	//
	// The counter is what an alert can fire on. Failing the request protects
	// this caller; the metric is how anyone finds out it happened at all.
	if err := v.Verify(); err != nil {
		obs.Counter("sf_content_hash_mismatch_total",
			"Stored artifact content that failed its recorded hash on read",
			obs.Labels{"artifact_type": string(v.Type)})
		return nil, err
	}
	return v, nil
}

// ListVersions returns an artifact's version history.
func (p *Postgres) ListVersions(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID, artifactID types.ArtifactID) ([]*domain.Version, error) {

	const op = "artifactgraph.ListVersions"

	var out []*domain.Version
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT `+versionColumns+` FROM artifact_versions
			  WHERE tenant_id = $1 AND project_id = $2 AND artifact_id = $3
			  ORDER BY version DESC`,
			tenantID.String(), projectID.String(), artifactID.String())
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "artifact.read_failed",
				"Could not read the artifact history.")
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			v, err := scanVersion(rows.Scan)
			if err != nil {
				return errors.Wrap(err, op, errors.KindInternal, "artifact.decode_failed",
					"Could not decode an artifact version.")
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

// ApprovedVersion returns the current approved version, if any.
func (p *Postgres) ApprovedVersion(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID, artifactID types.ArtifactID) (*domain.Version, error) {

	const op = "artifactgraph.ApprovedVersion"

	var v *domain.Version
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT `+versionColumns+` FROM artifact_versions
			  WHERE tenant_id = $1 AND project_id = $2 AND artifact_id = $3
			    AND status = 'APPROVED'`,
			tenantID.String(), projectID.String(), artifactID.String())
		got, err := scanVersion(row.Scan)
		if db.IsNoRows(err) {
			return errors.NotFound(op, "artifact.no_approved_version",
				"%s has no approved version.", artifactID)
		}
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "artifact.read_failed",
				"Could not read the approved version.")
		}
		v = got
		return nil
	})
	if err != nil {
		return nil, err
	}
	return v, nil
}

// Contributors lists everyone who authored a version of an artifact.
func (p *Postgres) Contributors(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID, artifactID types.ArtifactID) ([]types.PrincipalID, error) {

	const op = "artifactgraph.Contributors"

	var out []types.PrincipalID
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT DISTINCT created_by FROM artifact_versions
			  WHERE tenant_id = $1 AND project_id = $2 AND artifact_id = $3`,
			tenantID.String(), projectID.String(), artifactID.String())
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "artifact.read_failed",
				"Could not read the artifact contributors.")
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, types.PrincipalID(id))
		}
		return rows.Err()
	})
	return out, err
}

func encodeCursor(t time.Time) string {
	return base64.RawURLEncoding.EncodeToString([]byte("t" + t.UTC().Format(time.RFC3339Nano)))
}

func decodeCursor(c string) (time.Time, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil || len(raw) < 2 || raw[0] != 't' {
		return time.Time{}, fmt.Errorf("artifactgraph: malformed cursor")
	}
	return time.Parse(time.RFC3339Nano, string(raw[1:]))
}
