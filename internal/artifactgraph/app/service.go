// Package app holds the artifact graph use cases.
//
// The sealing sequence in Approve is the platform's most important code path.
// Its ordering is deliberate and documented inline: evidence is written to
// write-once storage before the database row is sealed, so a crash leaves an
// orphaned (harmless, content-addressed) evidence object rather than an approval
// with no evidence behind it.
package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/specforge/specforge/internal/artifactgraph/domain"
	auditapp "github.com/specforge/specforge/internal/audit/app"
	auditdomain "github.com/specforge/specforge/internal/audit/domain"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/fsm"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/httpx"
	"github.com/specforge/specforge/internal/platform/id"
	"github.com/specforge/specforge/internal/platform/jcs"
	"github.com/specforge/specforge/internal/platform/objstore"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/outbox"
	"github.com/specforge/specforge/internal/platform/types"
)

// Repository is the artifact graph persistence port.
type Repository interface {
	CreateArtifact(ctx context.Context, tx db.Tx, a *domain.Artifact) error
	UpdateArtifact(ctx context.Context, tx db.Tx, a *domain.Artifact) error
	GetArtifact(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
		artifactID types.ArtifactID) (*domain.Artifact, error)
	ListArtifacts(ctx context.Context, f ArtifactFilter) ([]*domain.Artifact, string, error)

	CreateVersion(ctx context.Context, tx db.Tx, v *domain.Version) error
	UpdateVersion(ctx context.Context, tx db.Tx, v *domain.Version) error
	// GetVersion verifies the content hash before returning.
	GetVersion(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
		artifactID types.ArtifactID, version int) (*domain.Version, error)
	ListVersions(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
		artifactID types.ArtifactID) ([]*domain.Version, error)
	ApprovedVersion(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
		artifactID types.ArtifactID) (*domain.Version, error)
	// Contributors lists everyone who authored a version of this artifact, for
	// the four-eyes check.
	Contributors(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
		artifactID types.ArtifactID) ([]types.PrincipalID, error)

	CreateLink(ctx context.Context, tx db.Tx, l *domain.TraceLink) error
	UpdateLink(ctx context.Context, tx db.Tx, l *domain.TraceLink) error
	GetLink(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
		linkID types.LinkID) (*domain.TraceLink, error)
	ListLinks(ctx context.Context, f LinkFilter) ([]*domain.TraceLink, error)
	Traverse(ctx context.Context, spec domain.TraverseSpec) (domain.Paths, error)
	// NextArtifactSequence allocates the next numeric suffix for an artifact id
	// within a type and area, so identifiers do not collide.
	NextArtifactSequence(ctx context.Context, tx db.Tx, tenantID types.TenantID,
		projectID types.ProjectID, prefix string) (int, error)
}

// ArtifactFilter narrows an artifact query.
type ArtifactFilter struct {
	TenantID  types.TenantID
	ProjectID types.ProjectID
	Type      types.ArtifactType
	Status    fsm.State
	Label     [2]string
	Cursor    string
	Limit     int
}

// LinkFilter narrows a link query.
type LinkFilter struct {
	TenantID  types.TenantID
	ProjectID types.ProjectID
	From      *types.ArtifactID
	To        *types.ArtifactID
	Type      types.LinkType
	Status    types.LinkStatus
	Limit     int
}

// ProjectReader is the tenancy port the graph needs, kept narrow so the modules
// stay decoupled.
type ProjectReader interface {
	ProjectKey(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID) (string, error)
	BumpGraphVersion(ctx context.Context, tx db.Tx, tenantID types.TenantID, projectID types.ProjectID) (int64, error)
}

// GateEvaluator is the governance port.
//
// Phase 1 ships a permissive evaluator; Phase 10 replaces it with the policy
// engine. The interface exists now so that the approval path already routes
// through governance and does not have to be restructured later.
type GateEvaluator interface {
	// Evaluate returns the gate decisions bound to an artifact type, or an error
	// when a gate blocks. Blocking decisions must prevent the approval.
	Evaluate(ctx context.Context, subject GateSubject) ([]domain.GateDecisionRef, error)
}

// GateSubject describes what a gate is being asked about.
type GateSubject struct {
	TenantID     types.TenantID
	ProjectID    types.ProjectID
	ArtifactID   types.ArtifactID
	ArtifactType types.ArtifactType
	Version      int
	Actor        types.PrincipalID
}

// Service is the artifact graph application service.
type Service struct {
	db       *db.DB
	repo     Repository
	audit    *auditapp.Service
	outbox   outbox.Writer
	authz    *authz.Evaluator
	content  objstore.Store
	evidence objstore.Store
	buckets  Buckets
	projects ProjectReader
	gates    GateEvaluator
	maxDepth int
	logger   *slog.Logger
}

// Buckets names the storage buckets.
type Buckets struct {
	Content  string
	Evidence string
}

// NewService builds the artifact graph service.
func NewService(database *db.DB, repo Repository, audit *auditapp.Service,
	ob outbox.Writer, ev *authz.Evaluator, content, evidence objstore.Store,
	buckets Buckets, projects ProjectReader, gates GateEvaluator,
	maxDepth int, logger *slog.Logger) *Service {

	if maxDepth <= 0 {
		maxDepth = 12
	}
	return &Service{
		db: database, repo: repo, audit: audit, outbox: ob, authz: ev,
		content: content, evidence: evidence, buckets: buckets,
		projects: projects, gates: gates, maxDepth: maxDepth, logger: logger,
	}
}

// CreateInput is the create-artifact command.
type CreateInput struct {
	TenantID      types.TenantID
	ProjectID     types.ProjectID
	ArtifactID    types.ArtifactID // optional; allocated from the type prefix when empty
	Area          string           // optional id segment, e.g. "AUTH" in SPEC-AUTH-001
	Type          types.ArtifactType
	Title         string
	ContentSchema string
	Content       json.RawMessage
	Generator     domain.Generator
	Labels        map[string]string
	// Parent and Source record structure and derivation.
	Parent *types.ArtifactRef
	Source *types.ArtifactRef
}

// Create creates an artifact and its first draft version.
func (s *Service) Create(ctx context.Context, in CreateInput, actor authz.Principal) (*domain.Version, error) {
	const op = "artifactgraph.Create"

	if err := s.authz.Require(actor, authz.ArtifactCreate, authz.Resource{
		Type: "artifact", TenantID: in.TenantID, ProjectID: in.ProjectID.String(),
		ArtifactType: in.Type,
	}); err != nil {
		return nil, err
	}
	if !in.Type.Valid() {
		return nil, errors.Invalid(op, "artifact.type_invalid",
			"Artifact type %q is not recognised.", in.Type)
	}

	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: in.TenantID, ProjectID: &in.ProjectID, PrincipalID: actor.ID,
	})

	if in.Generator.Kind == "" {
		in.Generator.Kind = types.GeneratedByUser
	}

	var version *domain.Version
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		artifactID := in.ArtifactID
		if artifactID == "" {
			generated, err := s.allocateID(ctx, tx, in)
			if err != nil {
				return err
			}
			artifactID = generated
		}
		if _, err := types.ParseArtifactID(artifactID.String()); err != nil {
			return errors.Invalid(op, "artifact.id_invalid", "%s", err.Error())
		}

		v, err := domain.NewVersion(in.TenantID, in.ProjectID, artifactID, in.Type,
			in.ContentSchema, in.Content, in.Generator, actor.ID)
		if err != nil {
			return err
		}
		v.ParentArtifact = in.Parent
		v.SourceArtifact = in.Source
		if h, herr := v.ComputeHash(); herr == nil {
			v.ContentHash = h
		}

		artifact := &domain.Artifact{
			TenantID: in.TenantID, ProjectID: in.ProjectID, ID: artifactID,
			Type: in.Type, Title: in.Title, CurrentVersion: 1,
			Status: domain.StatusDraft, Labels: in.Labels,
			CreatedBy: actor.ID, CreatedAt: types.Now(),
			UpdatedAt: types.Now(), Version: 1,
		}
		if artifact.Labels == nil {
			artifact.Labels = map[string]string{}
		}

		if err := s.repo.CreateArtifact(ctx, tx, artifact); err != nil {
			return err
		}
		if err := s.repo.CreateVersion(ctx, tx, v); err != nil {
			return err
		}
		if _, err := s.projects.BumpGraphVersion(ctx, tx, in.TenantID, in.ProjectID); err != nil {
			return err
		}

		if err := s.appendAudit(ctx, tx, actor, v, "artifact.create",
			auditdomain.SeverityNotice, map[string]any{
				"artifact_type": string(in.Type),
				"generator":     string(in.Generator.Kind),
			}); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, actor, v, "artifact.created", map[string]any{
			"artifact_id": artifactID.String(), "artifact_type": string(in.Type),
			"version": 1, "content_hash": v.ContentHash.String(),
			"generator": string(in.Generator.Kind),
		}); err != nil {
			return err
		}

		version = v
		return nil
	})
	if err != nil {
		return nil, err
	}

	obs.Counter("sf_artifact_versions_created_total", "Artifact versions created",
		obs.Labels{"type": string(in.Type), "generator_kind": string(in.Generator.Kind)})
	return version, nil
}

// allocateID mints the next identifier for a type and optional area.
func (s *Service) allocateID(ctx context.Context, tx db.Tx, in CreateInput) (types.ArtifactID, error) {
	prefix := in.Type.Prefix()
	if in.Area != "" {
		prefix = prefix + "-" + in.Area
	}
	n, err := s.repo.NextArtifactSequence(ctx, tx, in.TenantID, in.ProjectID, prefix)
	if err != nil {
		return "", err
	}
	return types.ArtifactID(fmt.Sprintf("%s-%03d", prefix, n)), nil
}

// UpdateDraft replaces a draft version's content.
func (s *Service) UpdateDraft(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	artifactID types.ArtifactID, version int, content json.RawMessage,
	expectedVersionNo int64, actor authz.Principal) (*domain.Version, error) {

	const op = "artifactgraph.UpdateDraft"

	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: tenantID, ProjectID: &projectID, PrincipalID: actor.ID,
	})

	var updated *domain.Version
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		v, err := s.repo.GetVersion(ctx, tenantID, projectID, artifactID, version)
		if err != nil {
			return err
		}
		if err := s.authz.Require(actor, authz.ArtifactEdit, authz.Resource{
			Type: "artifact", ID: artifactID.String(), TenantID: tenantID,
			ProjectID: projectID.String(), CreatedBy: v.CreatedBy, ArtifactType: v.Type,
		}); err != nil {
			return err
		}
		if v.Sealed() {
			return errors.Conflict(op, "artifact.sealed_immutable",
				"%s version %d is %s and cannot be modified. Create a new version instead.",
				artifactID, version, v.Status)
		}
		if expectedVersionNo > 0 && v.VersionNo != expectedVersionNo {
			return errors.Conflict(op, "concurrency.stale_version",
				"The artifact was modified by another request. Reload and try again.")
		}
		if err := v.SetContent(content); err != nil {
			return err
		}
		if err := s.repo.UpdateVersion(ctx, tx, v); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, v, "artifact.edit",
			auditdomain.SeverityInfo, nil); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, actor, v, "artifact.updated", map[string]any{
			"artifact_id": artifactID.String(), "version": version,
			"content_hash": v.ContentHash.String(),
		}); err != nil {
			return err
		}
		updated = v
		return nil
	})
	return updated, err
}

// Transition fires a lifecycle event that is not the approval.
func (s *Service) Transition(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	artifactID types.ArtifactID, version int, event fsm.Event,
	comment string, actor authz.Principal) (*domain.Version, error) {

	const op = "artifactgraph.Transition"

	if event == domain.EventApprove {
		return nil, errors.Invalid(op, "artifact.use_approve",
			"Approval must go through the approval endpoint so that evidence is sealed.")
	}

	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: tenantID, ProjectID: &projectID, PrincipalID: actor.ID,
	})

	var result *domain.Version
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		v, err := s.repo.GetVersion(ctx, tenantID, projectID, artifactID, version)
		if err != nil {
			return err
		}
		out, err := s.fire(ctx, actor, v, event, projectID)
		if err != nil {
			return err
		}
		v.Status = out.To
		v.UpdatedAt = types.Now()

		if err := s.repo.UpdateVersion(ctx, tx, v); err != nil {
			return err
		}
		artifact, err := s.repo.GetArtifact(ctx, tenantID, projectID, artifactID)
		if err != nil {
			return err
		}
		artifact.Status = out.To
		if err := s.repo.UpdateArtifact(ctx, tx, artifact); err != nil {
			return err
		}

		if err := s.appendAudit(ctx, tx, actor, v, out.AuditAction,
			auditdomain.SeverityNotice, map[string]any{
				"from": string(out.From), "to": string(out.To), "comment": comment,
			}); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, actor, v, out.EmitEvent, map[string]any{
			"artifact_id": artifactID.String(), "version": version,
			"from": string(out.From), "to": string(out.To),
		}); err != nil {
			return err
		}
		result = v
		return nil
	})
	return result, err
}

// fire runs the state machine with the authorization check wired in.
func (s *Service) fire(ctx context.Context, actor authz.Principal, v *domain.Version,
	event fsm.Event, projectID types.ProjectID) (fsm.Outcome, error) {

	contributors, err := s.repo.Contributors(ctx, v.TenantID, projectID, v.ArtifactID)
	if err != nil {
		return fsm.Outcome{}, err
	}
	res := authz.Resource{
		Type: "artifact", ID: v.ArtifactID.String(), TenantID: v.TenantID,
		ProjectID: projectID.String(), CreatedBy: v.CreatedBy,
		Contributors: contributors, ArtifactType: v.Type,
	}

	check := func(ctx context.Context, permission string) error {
		p, perr := authz.ParsePermission(permission)
		if perr != nil {
			return errors.Internal("artifactgraph.fire", "authz.unknown_permission",
				"Transition declares unknown permission %q.", permission)
		}
		return s.authz.Require(actor, p, res)
	}
	if actor.Kind == authz.KindSystem {
		check = nil
	}
	return domain.Machine.Fire(ctx, v.Status, event, v, check)
}

// ApproveInput is the approval command.
type ApproveInput struct {
	TenantID   types.TenantID
	ProjectID  types.ProjectID
	ArtifactID types.ArtifactID
	Version    int
	Comment    string
}

// Approve seals an artifact version.
//
// The ordering below is the heart of the platform and is not incidental:
//
//  1. Governance gates run first. A blocked gate stops the approval before any
//     evidence exists, so a blocked attempt leaves no trace of an approval.
//  2. Segregation of duties and step-up are enforced by the state machine's
//     permission check, which routes through the ABAC evaluator.
//  3. Content and evidence are written to write-once storage BEFORE the row is
//     sealed. Both writes are content-addressed and idempotent, so a crash here
//     leaves harmless orphans. The reverse order could produce an approval whose
//     evidence does not exist, which is unrecoverable.
//  4. The database transaction then seals the version, supersedes the previous
//     approved version, appends the audit record and writes the domain event —
//     atomically. Either all four happen or none do.
func (s *Service) Approve(ctx context.Context, in ApproveInput, actor authz.Principal) (*domain.Version, error) {
	const op = "artifactgraph.Approve"

	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: in.TenantID, ProjectID: &in.ProjectID, PrincipalID: actor.ID,
	})

	current, err := s.repo.GetVersion(ctx, in.TenantID, in.ProjectID, in.ArtifactID, in.Version)
	if err != nil {
		return nil, err
	}
	if current.Status != domain.StatusUserReview {
		return nil, errors.Precondition(op, "artifact.not_in_review",
			"%s version %d is %s; only a version in review can be approved.",
			in.ArtifactID, in.Version, current.Status)
	}

	// Step 1: governance.
	gateDecisions, err := s.gates.Evaluate(ctx, GateSubject{
		TenantID: in.TenantID, ProjectID: in.ProjectID, ArtifactID: in.ArtifactID,
		ArtifactType: current.Type, Version: in.Version, Actor: actor.ID,
	})
	if err != nil {
		return nil, err
	}

	// Step 2: authorization, including four-eyes and step-up, via the FSM.
	if _, err := s.fire(ctx, actor, current, domain.EventApprove, in.ProjectID); err != nil {
		return nil, err
	}

	// Step 3: write-once content and evidence, before anything is sealed.
	canonical, err := jcs.CanonicalizeJSON(current.Content)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindInternal, "artifact.canonicalize_failed",
			"Could not canonicalize the artifact content.")
	}
	contentKey := objstore.ContentKey(in.TenantID, &in.ProjectID, hash.ContentOfBytes(canonical))
	if _, err := s.content.PutAt(ctx, s.buckets.Content, contentKey, canonical, objstore.PutOptions{
		MediaType: "application/json",
		Metadata: map[string]string{
			"artifact_id": in.ArtifactID.String(),
			"version":     fmt.Sprint(in.Version),
		},
	}); err != nil {
		return nil, err
	}

	// One approval instant, used for the evidence document and for the sealed
	// row alike. Two clock reads would produce two different approval times for
	// a single approval, and the evidence would contradict the record.
	approvedAt := types.Now()

	evidenceID := "EVD-" + id.NewToken(8)
	evidenceDoc := map[string]any{
		"evidence_id":        evidenceID,
		"tenant_id":          in.TenantID.String(),
		"project_id":         in.ProjectID.String(),
		"artifact_id":        in.ArtifactID.String(),
		"artifact_type":      string(current.Type),
		"version":            in.Version,
		"content_hash":       current.ContentHash.String(),
		"content_ref":        contentKey,
		"approver":           actor.ID.String(),
		"approver_display":   actor.Display,
		"approver_auth_time": actor.AuthTime.UTC().Format(time.RFC3339),
		"approver_amr":       actor.AMR,
		"approval_comment":   in.Comment,
		"approved_at":        approvedAt.Format(time.RFC3339Nano),
		"gate_decisions":     gateDecisions,
		"previous_version":   current.PreviousVersion,
		"change_summary":     current.ChangeSummary,
		"generator":          current.Generator,
	}
	evidenceBytes, err := jcs.Canonicalize(evidenceDoc)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindInternal, "artifact.evidence_encode_failed",
			"Could not encode the approval evidence.")
	}
	evidenceDigest := hash.ContentOfBytes(evidenceBytes)
	evidenceKey := objstore.TenantKey(in.TenantID, &in.ProjectID,
		"evidence/"+hash.StorageKey(evidenceDigest))

	evidenceObj, err := s.evidence.PutAt(ctx, s.buckets.Evidence, evidenceKey, evidenceBytes,
		objstore.PutOptions{
			MediaType: "application/vnd.specforge.approval+json",
			// Write-once: evidence that can be replaced is not evidence.
			Lock:        true,
			RetainUntil: approvedAt.AddDate(7, 0, 0),
			Metadata: map[string]string{
				"artifact_id": in.ArtifactID.String(),
				"version":     fmt.Sprint(in.Version),
				"approver":    actor.ID.String(),
			},
		})
	if err != nil {
		return nil, err
	}

	evidence := domain.ApprovalEvidence{
		EvidenceID:       evidenceID,
		Digest:           evidenceDigest,
		MediaType:        "application/vnd.specforge.approval+json",
		StorageRef:       evidenceObj.Key,
		GateDecisions:    gateDecisions,
		ApproverAuthTime: actor.AuthTime.UTC(),
	}

	// Step 4: seal atomically.
	var sealed *domain.Version
	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		v, err := s.repo.GetVersion(ctx, in.TenantID, in.ProjectID, in.ArtifactID, in.Version)
		if err != nil {
			return err
		}
		// Re-check under the transaction: another request may have approved it
		// between the read above and here.
		if v.Status != domain.StatusUserReview {
			return errors.Conflict(op, "artifact.not_in_review",
				"%s version %d is no longer in review.", in.ArtifactID, in.Version)
		}

		// Supersede the previous approved version first, so the partial unique
		// index never sees two approved rows.
		prior, err := s.repo.ApprovedVersion(ctx, in.TenantID, in.ProjectID, in.ArtifactID)
		if err != nil && errors.KindOf(err) != errors.KindNotFound {
			return err
		}
		if prior != nil && prior.Version != in.Version {
			prior.Status = domain.StatusSuperseded
			if err := s.repo.UpdateVersion(ctx, tx, prior); err != nil {
				return err
			}
			if err := s.emit(ctx, tx, actor, prior, "artifact.superseded", map[string]any{
				"artifact_id":         in.ArtifactID.String(),
				"superseded_version":  prior.Version,
				"superseding_version": in.Version,
			}); err != nil {
				return err
			}
		}

		if err := v.SealApproval(actor.ID, in.Comment, evidence, approvedAt); err != nil {
			return err
		}
		if err := s.repo.UpdateVersion(ctx, tx, v); err != nil {
			return err
		}

		artifact, err := s.repo.GetArtifact(ctx, in.TenantID, in.ProjectID, in.ArtifactID)
		if err != nil {
			return err
		}
		artifact.Status = domain.StatusApproved
		artifact.CurrentVersion = in.Version
		if err := s.repo.UpdateArtifact(ctx, tx, artifact); err != nil {
			return err
		}
		if _, err := s.projects.BumpGraphVersion(ctx, tx, in.TenantID, in.ProjectID); err != nil {
			return err
		}

		if err := s.appendAudit(ctx, tx, actor, v, "artifact.approve",
			auditdomain.SeverityWarning, map[string]any{
				"approval_comment": in.Comment,
				"evidence_id":      evidenceID,
				"evidence_digest":  evidenceDigest.String(),
				"gate_decisions":   gateDecisions,
				"artifact_type":    string(v.Type),
			}); err != nil {
			return err
		}

		eventType := "artifact.approved"
		if v.Type == types.ArtifactPRD {
			eventType = "prd.approved"
		}
		if err := s.emit(ctx, tx, actor, v, eventType, map[string]any{
			"artifact_id": in.ArtifactID.String(), "version": in.Version,
			"artifact_type":    string(v.Type),
			"content_hash":     v.ContentHash.String(),
			"approved_by":      actor.ID.String(),
			"approved_at":      v.ApprovedAt.Format(time.RFC3339Nano),
			"approval_comment": in.Comment,
			"approval_evidence": map[string]any{
				"evidence_id": evidenceID, "digest": evidenceDigest.String(),
			},
			"gate_decisions":   gateDecisions,
			"previous_version": v.PreviousVersion,
			"change_summary":   v.ChangeSummary,
		}); err != nil {
			return err
		}

		sealed = v
		return nil
	})
	if err != nil {
		return nil, err
	}

	obs.Counter("sf_approvals_total", "Artifact approvals",
		obs.Labels{"type": string(sealed.Type), "outcome": "approved"})
	s.logger.InfoContext(ctx, "artifact sealed",
		"artifact_id", in.ArtifactID, "version", in.Version,
		"content_hash", sealed.ContentHash.Short(), "evidence_id", evidenceID)
	return sealed, nil
}

// Revise creates the next draft version of an artifact.
func (s *Service) Revise(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	artifactID types.ArtifactID, changeSummary string, actor authz.Principal) (*domain.Version, error) {

	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: tenantID, ProjectID: &projectID, PrincipalID: actor.ID,
	})

	var next *domain.Version
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		artifact, err := s.repo.GetArtifact(ctx, tenantID, projectID, artifactID)
		if err != nil {
			return err
		}
		if err := s.authz.Require(actor, authz.ArtifactEdit, authz.Resource{
			Type: "artifact", ID: artifactID.String(), TenantID: tenantID,
			ProjectID: projectID.String(), CreatedBy: artifact.CreatedBy,
			ArtifactType: artifact.Type,
		}); err != nil {
			return err
		}

		latest, err := s.repo.GetVersion(ctx, tenantID, projectID, artifactID, artifact.CurrentVersion)
		if err != nil {
			return err
		}
		gen := domain.Generator{Kind: types.GeneratedByUser}
		v, err := latest.Revise(changeSummary, actor.ID, gen)
		if err != nil {
			return err
		}
		if err := s.repo.CreateVersion(ctx, tx, v); err != nil {
			return err
		}

		artifact.CurrentVersion = v.Version
		artifact.Status = domain.StatusDraft
		if err := s.repo.UpdateArtifact(ctx, tx, artifact); err != nil {
			return err
		}
		if _, err := s.projects.BumpGraphVersion(ctx, tx, tenantID, projectID); err != nil {
			return err
		}

		if err := s.appendAudit(ctx, tx, actor, v, "artifact.revise",
			auditdomain.SeverityNotice, map[string]any{
				"change_summary": changeSummary, "previous_version": latest.Version,
			}); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, actor, v, "artifact.version.created", map[string]any{
			"artifact_id": artifactID.String(), "version": v.Version,
			"previous_version": latest.Version, "change_summary": changeSummary,
			"content_hash": v.ContentHash.String(),
		}); err != nil {
			return err
		}
		next = v
		return nil
	})
	return next, err
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

// GetVersion returns a version, verifying its content hash.
func (s *Service) GetVersion(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	artifactID types.ArtifactID, version int, actor authz.Principal) (*domain.Version, error) {

	if err := s.authz.Require(actor, authz.ArtifactRead, authz.Resource{
		Type: "artifact", ID: artifactID.String(), TenantID: tenantID,
		ProjectID: projectID.String(),
	}); err != nil {
		return nil, err
	}
	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: tenantID, ProjectID: &projectID, PrincipalID: actor.ID,
	})
	return s.repo.GetVersion(ctx, tenantID, projectID, artifactID, version)
}

// GetArtifact returns an artifact's identity and history summary.
func (s *Service) GetArtifact(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	artifactID types.ArtifactID, actor authz.Principal) (*domain.Artifact, []*domain.Version, error) {

	if err := s.authz.Require(actor, authz.ArtifactRead, authz.Resource{
		Type: "artifact", ID: artifactID.String(), TenantID: tenantID,
		ProjectID: projectID.String(),
	}); err != nil {
		return nil, nil, err
	}
	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: tenantID, ProjectID: &projectID, PrincipalID: actor.ID,
	})
	a, err := s.repo.GetArtifact(ctx, tenantID, projectID, artifactID)
	if err != nil {
		return nil, nil, err
	}
	versions, err := s.repo.ListVersions(ctx, tenantID, projectID, artifactID)
	if err != nil {
		return nil, nil, err
	}
	return a, versions, nil
}

// List returns artifacts matching a filter.
func (s *Service) List(ctx context.Context, f ArtifactFilter, actor authz.Principal) ([]*domain.Artifact, string, error) {
	if err := s.authz.Require(actor, authz.ArtifactRead, authz.Resource{
		Type: "artifact", TenantID: f.TenantID, ProjectID: f.ProjectID.String(),
	}); err != nil {
		return nil, "", err
	}
	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: f.TenantID, ProjectID: &f.ProjectID, PrincipalID: actor.ID,
	})
	return s.repo.ListArtifacts(ctx, f)
}

// Evidence returns the stored approval evidence for a version, verified against
// its recorded digest.
func (s *Service) Evidence(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	artifactID types.ArtifactID, version int, actor authz.Principal) ([]byte, error) {

	const op = "artifactgraph.Evidence"

	v, err := s.GetVersion(ctx, tenantID, projectID, artifactID, version, actor)
	if err != nil {
		return nil, err
	}
	if v.ApprovalEvidence == nil {
		return nil, errors.NotFound(op, "artifact.no_evidence",
			"%s version %d has no approval evidence.", artifactID, version)
	}
	body, _, err := s.evidence.GetVerified(ctx, s.buckets.Evidence,
		v.ApprovalEvidence.StorageRef, v.ApprovalEvidence.Digest)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (s *Service) appendAudit(ctx context.Context, tx db.Tx, actor authz.Principal,
	v *domain.Version, action string, severity auditdomain.Severity, attrs map[string]any) error {

	projectID := v.ProjectID
	rec := auditdomain.New(v.TenantID, &projectID, action,
		auditdomain.OutcomeSuccess, severity,
		auditActor(actor),
		auditdomain.Target{
			Type: "Artifact", ID: v.ArtifactID.String(), Version: v.Version,
			ProjectID: projectID.String(), ContentHash: v.ContentHash.String(),
		})
	for k, val := range attrs {
		rec.WithAttr(k, val)
	}
	return s.audit.Append(ctx, tx, rec)
}

func (s *Service) emit(ctx context.Context, tx db.Tx, actor authz.Principal,
	v *domain.Version, eventType string, payload map[string]any) error {

	projectID := v.ProjectID
	ev, err := outbox.New(eventType, v.TenantID, &projectID,
		outbox.Aggregate{Type: "Artifact", ID: v.ArtifactID.String(), Version: v.Version},
		outbox.Actor{
			Kind: string(actor.Kind), PrincipalID: actor.ID.String(), Display: actor.Display,
		},
		outbox.Correlation{
			TraceID:   obs.TraceIDFrom(ctx),
			SpanID:    obs.SpanIDFrom(ctx),
			RequestID: httpx.RequestIDFrom(ctx),
		},
		payload)
	if err != nil {
		return errors.Wrap(err, "artifactgraph.emit", errors.KindInternal,
			"artifact.event_failed", "Could not record the artifact event.")
	}
	return s.outbox.Append(ctx, tx, ev)
}

func auditActor(p authz.Principal) auditdomain.Actor {
	a := auditdomain.Actor{
		Kind: string(p.Kind), PrincipalID: p.ID, Display: p.Display,
		Subject: p.Subject, Issuer: p.Issuer, BreakGlass: p.BreakGlass,
	}
	if p.OnBehalfOf != nil {
		a.OnBehalfOf = *p.OnBehalfOf
	}
	return a
}

// emitRaw publishes an event for a non-artifact aggregate in the graph module.
func (s *Service) emitRaw(ctx context.Context, tx db.Tx, actor authz.Principal,
	tenantID types.TenantID, projectID *types.ProjectID,
	aggType, aggID string, aggVersion int, eventType string, payload map[string]any) error {

	ev, err := outbox.New(eventType, tenantID, projectID,
		outbox.Aggregate{Type: aggType, ID: aggID, Version: aggVersion},
		outbox.Actor{
			Kind: string(actor.Kind), PrincipalID: actor.ID.String(), Display: actor.Display,
		},
		outbox.Correlation{
			TraceID:   obs.TraceIDFrom(ctx),
			SpanID:    obs.SpanIDFrom(ctx),
			RequestID: httpx.RequestIDFrom(ctx),
		},
		payload)
	if err != nil {
		return errors.Wrap(err, "artifactgraph.emitRaw", errors.KindInternal,
			"artifact.event_failed", "Could not record the event.")
	}
	return s.outbox.Append(ctx, tx, ev)
}
