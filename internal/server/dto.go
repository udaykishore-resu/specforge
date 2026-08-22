package server

import (
	"encoding/json"

	artifactdomain "github.com/specforge/specforge/internal/artifactgraph/domain"
	auditdomain "github.com/specforge/specforge/internal/audit/domain"
	tenancydomain "github.com/specforge/specforge/internal/tenancy/domain"
)

// The DTO layer is where the API contract is decided, separately from the domain
// model. Two rules apply:
//
//   - Nothing sensitive crosses this boundary. Secret hashes, storage
//     credentials and internal identifiers stay behind it.
//   - Every governed artifact carries its provenance and its content hash, so a
//     client can verify an artifact independently rather than trusting the API.

func tenantDTO(t *tenancydomain.Tenant) map[string]any {
	return map[string]any{
		"tenant_id":      t.ID.String(),
		"slug":           t.Slug,
		"name":           t.Name,
		"status":         string(t.Status),
		"isolation_mode": string(t.IsolationMode),
		"region":         t.Region,
		"settings":       t.Settings,
		"created_at":     t.CreatedAt,
		"updated_at":     t.UpdatedAt,
		"version_no":     t.Version,
	}
}

func projectDTO(p *tenancydomain.Project) map[string]any {
	return map[string]any{
		"project_id":    p.ID.String(),
		"tenant_id":     p.TenantID.String(),
		"key":           p.Key,
		"name":          p.Name,
		"description":   p.Description,
		"status":        string(p.Status),
		"pdlc_phase":    string(p.Phase),
		"graph_version": p.GraphVersion,
		"created_at":    p.CreatedAt,
		"updated_at":    p.UpdatedAt,
		"version_no":    p.Version,
	}
}

func artifactDTO(a *artifactdomain.Artifact) map[string]any {
	return map[string]any{
		"artifact_id":     a.ID.String(),
		"artifact_type":   string(a.Type),
		"title":           a.Title,
		"current_version": a.CurrentVersion,
		"status":          string(a.Status),
		"labels":          a.Labels,
		"created_by":      a.CreatedBy.String(),
		"created_at":      a.CreatedAt,
		"updated_at":      a.UpdatedAt,
	}
}

func versionDTO(v *artifactdomain.Version) map[string]any {
	out := map[string]any{
		"artifact_id":    v.ArtifactID.String(),
		"artifact_type":  string(v.Type),
		"version":        v.Version,
		"status":         string(v.Status),
		"content_schema": v.ContentSchema,
		"content":        json.RawMessage(v.Content),
		// The content hash is returned on every read so a client can verify the
		// payload independently. That is the point of content addressing.
		"content_hash":   v.ContentHash.String(),
		"change_summary": v.ChangeSummary,
		"generator":      v.Generator,
		"created_by":     v.CreatedBy.String(),
		"created_at":     v.CreatedAt,
		"updated_at":     v.UpdatedAt,
		"version_no":     v.VersionNo,
		"sealed":         v.Sealed(),
	}
	if v.ContentRef != "" {
		out["content_ref"] = v.ContentRef
	}
	if v.PreviousVersion != nil {
		out["previous_version"] = *v.PreviousVersion
	}
	if v.ParentArtifact != nil {
		out["parent_artifact"] = v.ParentArtifact
	}
	if v.SourceArtifact != nil {
		out["source_artifact"] = v.SourceArtifact
	}
	if v.ApprovedBy != nil {
		out["approved_by"] = v.ApprovedBy.String()
	}
	if v.ApprovedAt != nil {
		out["approved_at"] = *v.ApprovedAt
	}
	if v.ApprovalComment != "" {
		out["approval_comment"] = v.ApprovalComment
	}
	if v.ApprovalEvidence != nil {
		out["approval_evidence"] = v.ApprovalEvidence
	}
	if v.SealedAt != nil {
		out["sealed_at"] = *v.SealedAt
	}
	return out
}

func auditDTO(r *auditdomain.Record) map[string]any {
	out := map[string]any{
		"sequence":    r.Sequence,
		"id":          r.ID,
		"action":      r.Action,
		"outcome":     string(r.Outcome),
		"severity":    string(r.Severity),
		"actor":       r.Actor,
		"target":      r.Target,
		"attributes":  r.Attributes,
		"request_id":  r.RequestID,
		"trace_id":    r.TraceID,
		"occurred_at": r.OccurredAt,
		// The chain hashes are exposed so an auditor can verify the chain offline
		// without asking the platform to vouch for itself.
		"prev_hash":   r.PrevHash,
		"record_hash": r.RecordHash,
	}
	if r.ProjectID != nil {
		out["project_id"] = r.ProjectID.String()
	}
	return out
}
