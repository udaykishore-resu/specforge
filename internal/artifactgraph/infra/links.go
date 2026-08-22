package infra

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/artifactgraph/app"
	"github.com/specforge/specforge/internal/artifactgraph/domain"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/types"
)

const linkColumns = `tenant_id, project_id, link_id, from_artifact_id, from_version,
       to_artifact_id, to_version, link_type, origin, confidence, status,
       rationale, evidence, disposition_id, created_by, created_at, updated_at, version_no`

func scanLink(scan func(...any) error) (*domain.TraceLink, error) {
	var (
		l             domain.TraceLink
		tenantID      string
		projectID     string
		linkID        string
		fromID        string
		fromVer       int64
		toID          string
		toVer         int64
		linkType      string
		origin        string
		status        string
		confidenceStr string
		evidenceRaw   []byte
		dispositionID *string
		createdBy     string
		createdAt     time.Time
		updatedAt     time.Time
	)
	if err := scan(&tenantID, &projectID, &linkID, &fromID, &fromVer,
		&toID, &toVer, &linkType, &origin, &confidenceStr, &status,
		&l.Rationale, &evidenceRaw, &dispositionID, &createdBy,
		&createdAt, &updatedAt, &l.VersionNo); err != nil {
		return nil, err
	}

	l.TenantID = types.TenantID(tenantID)
	l.ProjectID = types.ProjectID(projectID)
	l.LinkID = types.LinkID(linkID)
	l.From = types.ArtifactRef{ArtifactID: types.ArtifactID(fromID), Version: int(fromVer)}
	l.To = types.ArtifactRef{ArtifactID: types.ArtifactID(toID), Version: int(toVer)}
	l.Type = types.LinkType(linkType)
	l.Origin = types.LinkOrigin(origin)
	l.Status = types.LinkStatus(status)
	l.CreatedBy = types.PrincipalID(createdBy)
	l.CreatedAt = createdAt.UTC()
	l.UpdatedAt = updatedAt.UTC()
	l.DispositionID = dispositionID

	// numeric arrives as text from the driver; parse rather than assume float.
	if _, err := fmt.Sscanf(confidenceStr, "%f", &l.Confidence); err != nil {
		l.Confidence = 0
	}
	if len(evidenceRaw) > 0 {
		l.Evidence = json.RawMessage(append([]byte(nil), evidenceRaw...))
	}
	return &l, nil
}

// CreateLink inserts a trace link.
func (p *Postgres) CreateLink(ctx context.Context, tx db.Tx, l *domain.TraceLink) error {
	const op = "artifactgraph.CreateLink"

	var evidence any
	if len(l.Evidence) > 0 {
		evidence = string(l.Evidence)
	}
	var disposition any
	if l.DispositionID != nil {
		disposition = *l.DispositionID
	}

	_, err := tx.ExecContext(ctx, `
		INSERT INTO trace_links (tenant_id, project_id, link_id,
		  from_artifact_id, from_version, to_artifact_id, to_version,
		  link_type, origin, confidence, status, rationale, evidence,
		  disposition_id, created_by, created_at, updated_at, version_no)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15,$16,$17,$18)`,
		l.TenantID.String(), l.ProjectID.String(), l.LinkID.String(),
		l.From.ArtifactID.String(), int64(l.From.Version),
		l.To.ArtifactID.String(), int64(l.To.Version),
		string(l.Type), string(l.Origin), fmt.Sprintf("%.3f", l.Confidence),
		string(l.Status), l.Rationale, evidence, disposition,
		l.CreatedBy.String(), l.CreatedAt, l.UpdatedAt, l.VersionNo)

	if err != nil {
		return translateLinkError(op, err)
	}
	return nil
}

// UpdateLink writes a trace link.
func (p *Postgres) UpdateLink(ctx context.Context, tx db.Tx, l *domain.TraceLink) error {
	const op = "artifactgraph.UpdateLink"

	var disposition any
	if l.DispositionID != nil {
		disposition = *l.DispositionID
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE trace_links
		   SET status = $4, rationale = $5, disposition_id = $6,
		       updated_at = now(), version_no = version_no + 1
		 WHERE tenant_id = $1 AND project_id = $2 AND link_id = $3 AND version_no = $7`,
		l.TenantID.String(), l.ProjectID.String(), l.LinkID.String(),
		string(l.Status), l.Rationale, disposition, l.VersionNo)
	if err != nil {
		return translateLinkError(op, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.Conflict(op, "concurrency.stale_version",
			"The link was modified by another request. Reload and try again.")
	}
	l.VersionNo++
	return nil
}

func translateLinkError(op string, err error) error {
	if constraint, ok := db.ConstraintViolation(err); ok {
		switch {
		case strings.Contains(constraint, "llm_link_needs_disposition"):
			// The database refuses to let AI-proposed traceability become
			// authoritative without a recorded governance decision.
			return errors.Precondition(op, "link.disposition_required",
				"An AI-proposed link cannot be accepted without a recorded governance decision.")
		case strings.Contains(constraint, "trace_links_unique"):
			return errors.Conflict(op, "link.duplicate",
				"An identical link already exists between these artifact versions.")
		case strings.Contains(constraint, "no_self_link"):
			return errors.Invalid(op, "link.self_reference",
				"An artifact version cannot link to itself.")
		}
	}
	if db.IsForeignKeyViolation(err) {
		return errors.Invalid(op, "link.endpoint_missing",
			"One of the link endpoints does not exist in this project.")
	}
	if db.IsUniqueViolation(err) {
		return errors.Conflict(op, "link.duplicate",
			"An identical link already exists between these artifact versions.")
	}
	if db.IsCheckViolation(err) {
		return errors.Precondition(op, "link.constraint_violation",
			"The link violates a graph constraint.")
	}
	return errors.Wrap(err, op, errors.KindUnavailable, "link.write_failed",
		"Could not write the trace link.")
}

// GetLink loads a link.
func (p *Postgres) GetLink(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID, linkID types.LinkID) (*domain.TraceLink, error) {

	const op = "artifactgraph.GetLink"

	var l *domain.TraceLink
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT `+linkColumns+` FROM trace_links
			  WHERE tenant_id = $1 AND project_id = $2 AND link_id = $3`,
			tenantID.String(), projectID.String(), linkID.String())
		got, err := scanLink(row.Scan)
		if db.IsNoRows(err) {
			return errors.NotFound(op, "link.not_found", "The trace link was not found.")
		}
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "link.read_failed",
				"Could not read the trace link.")
		}
		l = got
		return nil
	})
	return l, err
}

// ListLinks returns links matching a filter.
func (p *Postgres) ListLinks(ctx context.Context, f app.LinkFilter) ([]*domain.TraceLink, error) {
	const op = "artifactgraph.ListLinks"

	conds := []string{"tenant_id = $1", "project_id = $2"}
	args := []any{f.TenantID.String(), f.ProjectID.String()}
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.From != nil {
		add("from_artifact_id = $%d", f.From.String())
	}
	if f.To != nil {
		add("to_artifact_id = $%d", f.To.String())
	}
	if f.Type != "" {
		add("link_type = $%d", string(f.Type))
	}
	if f.Status != "" {
		add("status = $%d", string(f.Status))
	}

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	args = append(args, int64(limit))

	query := `SELECT ` + linkColumns + ` FROM trace_links WHERE ` +
		strings.Join(conds, " AND ") +
		fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, len(args))

	var out []*domain.TraceLink
	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "link.read_failed",
				"Could not list trace links.")
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			l, err := scanLink(rows.Scan)
			if err != nil {
				return errors.Wrap(err, op, errors.KindInternal, "link.decode_failed",
					"Could not decode a trace link.")
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Traversal
// ---------------------------------------------------------------------------

// traverseSQL walks the graph with a recursive CTE.
//
// Two safety properties are built into the query rather than left to the caller:
// the `path` array is checked before each step so a cycle terminates instead of
// recursing forever, and `depth` is bounded so a pathological graph cannot
// produce an unbounded result set.
//
// $6 selects the direction: 'UPSTREAM' follows edges from the start artifact
// outward along `from`, 'DOWNSTREAM' follows them backwards along `to`.
const traverseSQL = `
WITH RECURSIVE walk AS (
    SELECT
        l.link_id,
        l.from_artifact_id, l.from_version,
        l.to_artifact_id,   l.to_version,
        l.link_type, l.origin, l.confidence, l.status,
        CASE WHEN $6 = 'UPSTREAM' THEN l.to_artifact_id ELSE l.from_artifact_id END AS node_id,
        CASE WHEN $6 = 'UPSTREAM' THEN l.to_version     ELSE l.from_version     END AS node_version,
        1 AS depth,
        ARRAY[$3::text] AS visited
      FROM trace_links l
     WHERE l.tenant_id = $1 AND l.project_id = $2
       AND (l.status = 'ACCEPTED' OR $7)
       AND CASE WHEN $6 = 'UPSTREAM'
                THEN l.from_artifact_id = $3 AND l.from_version = $4
                ELSE l.to_artifact_id   = $3 AND l.to_version   = $4
           END

    UNION ALL

    SELECT
        l.link_id,
        l.from_artifact_id, l.from_version,
        l.to_artifact_id,   l.to_version,
        l.link_type, l.origin, l.confidence, l.status,
        CASE WHEN $6 = 'UPSTREAM' THEN l.to_artifact_id ELSE l.from_artifact_id END,
        CASE WHEN $6 = 'UPSTREAM' THEN l.to_version     ELSE l.from_version     END,
        w.depth + 1,
        w.visited || w.node_id
      FROM trace_links l
      JOIN walk w
        ON CASE WHEN $6 = 'UPSTREAM'
                THEN l.from_artifact_id = w.node_id AND l.from_version = w.node_version
                ELSE l.to_artifact_id   = w.node_id AND l.to_version   = w.node_version
           END
     WHERE l.tenant_id = $1 AND l.project_id = $2
       AND (l.status = 'ACCEPTED' OR $7)
       AND w.depth < $5
       AND NOT (w.node_id = ANY(w.visited))
)
SELECT w.node_id, w.node_version, w.depth,
       w.from_artifact_id, w.from_version, w.to_artifact_id, w.to_version,
       w.link_type, w.origin, w.confidence, w.status,
       coalesce(a.artifact_type, ''), coalesce(a.title, ''), coalesce(v.status, '')
  FROM walk w
  LEFT JOIN artifacts a
    ON a.tenant_id = $1 AND a.project_id = $2 AND a.artifact_id = w.node_id
  LEFT JOIN artifact_versions v
    ON v.tenant_id = $1 AND v.project_id = $2
   AND v.artifact_id = w.node_id AND v.version = w.node_version
 ORDER BY w.depth, w.node_id`

// Traverse walks the artifact graph and returns full paths.
//
// Paths, not just endpoints: an auditor needs to see the justification for each
// hop, and a UI needs to render the chain.
func (p *Postgres) Traverse(ctx context.Context, spec domain.TraverseSpec) (domain.Paths, error) {
	const op = "artifactgraph.Traverse"

	maxDepth := spec.MaxDepth
	if maxDepth <= 0 || maxDepth > 64 {
		maxDepth = 12
	}

	result := domain.Paths{Start: spec.Start, Direction: spec.Direction}
	typeFilter := map[types.ArtifactType]bool{}
	for _, t := range spec.ArtifactTypes {
		typeFilter[t] = true
	}

	err := p.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx, traverseSQL,
			spec.TenantID.String(), spec.ProjectID.String(),
			spec.Start.ArtifactID.String(), int64(spec.Start.Version),
			int64(maxDepth), string(spec.Direction), spec.IncludeProposed)
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "graph.traverse_failed",
				"Could not traverse the artifact graph.")
		}
		defer func() { _ = rows.Close() }()

		// Keep the shallowest path to each node: the shortest justification is
		// the one a reviewer wants to see first.
		seen := map[string]bool{}
		for rows.Next() {
			var (
				nodeID      string
				nodeVersion int64
				depth       int64
				fromID      string
				fromVer     int64
				toID        string
				toVer       int64
				linkType    string
				origin      string
				confidence  string
				linkStatus  string
				artType     string
				title       string
				verStatus   string
			)
			if err := rows.Scan(&nodeID, &nodeVersion, &depth,
				&fromID, &fromVer, &toID, &toVer,
				&linkType, &origin, &confidence, &linkStatus,
				&artType, &title, &verStatus); err != nil {
				return errors.Wrap(err, op, errors.KindInternal, "graph.decode_failed",
					"Could not decode a traversal row.")
			}

			key := fmt.Sprintf("%s@%d", nodeID, nodeVersion)
			if seen[key] {
				continue
			}
			seen[key] = true

			at := types.ArtifactType(artType)
			if len(typeFilter) > 0 && !typeFilter[at] {
				continue
			}

			var conf float64
			_, _ = fmt.Sscanf(confidence, "%f", &conf)

			result.Paths = append(result.Paths, domain.Path{
				Target: types.ArtifactRef{
					ArtifactID: types.ArtifactID(nodeID), Version: int(nodeVersion),
				},
				Type:   at,
				Title:  title,
				Status: verStatus,
				Depth:  int(depth),
				Hops: []domain.Hop{{
					From: types.ArtifactRef{
						ArtifactID: types.ArtifactID(fromID), Version: int(fromVer),
					},
					To: types.ArtifactRef{
						ArtifactID: types.ArtifactID(toID), Version: int(toVer),
					},
					LinkType:   types.LinkType(linkType),
					Origin:     types.LinkOrigin(origin),
					Confidence: conf,
					Status:     types.LinkStatus(linkStatus),
				}},
			})
			if int(depth) >= maxDepth {
				// The walk stopped at the bound rather than exhausting the graph,
				// so the caller is told the answer is partial.
				result.Truncated = true
			}
		}
		return rows.Err()
	})
	return result, err
}
