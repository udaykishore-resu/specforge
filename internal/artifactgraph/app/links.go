package app

import (
	"context"

	"github.com/specforge/specforge/internal/artifactgraph/domain"
	auditdomain "github.com/specforge/specforge/internal/audit/domain"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/id"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/types"
)

// LinkInput is the create-link command.
type LinkInput struct {
	TenantID   types.TenantID
	ProjectID  types.ProjectID
	From       types.ArtifactRef
	To         types.ArtifactRef
	Type       types.LinkType
	Origin     types.LinkOrigin
	Confidence float64
	Rationale  string
}

// CreateLink records a typed relationship between two artifact versions.
func (s *Service) CreateLink(ctx context.Context, in LinkInput, actor authz.Principal) (*domain.TraceLink, error) {
	const op = "artifactgraph.CreateLink"

	if err := s.authz.Require(actor, authz.LinkCreate, authz.Resource{
		Type: "link", TenantID: in.TenantID, ProjectID: in.ProjectID.String(),
	}); err != nil {
		return nil, err
	}

	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: in.TenantID, ProjectID: &in.ProjectID, PrincipalID: actor.ID,
	})

	linkID := types.LinkID(id.NewUUIDv7())
	link, err := domain.NewTraceLink(in.TenantID, in.ProjectID, linkID,
		in.From, in.To, in.Type, in.Origin, in.Confidence, actor.ID)
	if err != nil {
		return nil, err
	}
	link.Rationale = in.Rationale

	// A human creating a link is asserting it directly, so origin HUMAN is only
	// accepted when the actor really is one. A service account cannot launder an
	// inferred link into an accepted one by claiming human origin.
	if in.Origin == types.OriginHuman && actor.IsMachine() {
		return nil, errors.Forbidden(op, "link.origin_not_permitted",
			"A service account cannot assert a link as human-authored.")
	}

	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := s.repo.CreateLink(ctx, tx, link); err != nil {
			return err
		}
		if _, err := s.projects.BumpGraphVersion(ctx, tx, in.TenantID, in.ProjectID); err != nil {
			return err
		}

		projectID := in.ProjectID
		rec := auditdomain.New(in.TenantID, &projectID, "trace_link.create",
			auditdomain.OutcomeSuccess, auditdomain.SeverityInfo,
			auditActor(actor),
			auditdomain.Target{
				Type: "TraceLink", ID: linkID.String(), ProjectID: projectID.String(),
			}).
			WithAttr("from", in.From.String()).
			WithAttr("to", in.To.String()).
			WithAttr("link_type", string(in.Type)).
			WithAttr("origin", string(in.Origin)).
			WithAttr("confidence", in.Confidence).
			WithAttr("status", string(link.Status))
		if err := s.audit.Append(ctx, tx, rec); err != nil {
			return err
		}

		eventType := "trace_link.proposed"
		if link.Status == types.LinkAccepted {
			eventType = "trace_link.accepted"
		}
		return s.emitLink(ctx, tx, actor, link, eventType)
	})
	if err != nil {
		return nil, err
	}

	obs.Counter("sf_trace_links_total", "Trace links created",
		obs.Labels{"type": string(in.Type), "origin": string(in.Origin), "status": string(link.Status)})
	return link, nil
}

// AcceptLink accepts a proposed link.
//
// An LLM-proposed link requires a disposition identifier. That requirement is
// enforced here, in the repository and by a database CHECK constraint, because
// it is the single rule that keeps model output from silently becoming
// authoritative traceability.
func (s *Service) AcceptLink(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	linkID types.LinkID, dispositionID string, actor authz.Principal) (*domain.TraceLink, error) {

	if err := s.authz.Require(actor, authz.LinkAccept, authz.Resource{
		Type: "link", ID: linkID.String(), TenantID: tenantID, ProjectID: projectID.String(),
	}); err != nil {
		return nil, err
	}

	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: tenantID, ProjectID: &projectID, PrincipalID: actor.ID,
	})

	var accepted *domain.TraceLink
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		link, err := s.repo.GetLink(ctx, tenantID, projectID, linkID)
		if err != nil {
			return err
		}
		if err := link.Accept(dispositionID, actor.ID); err != nil {
			return err
		}
		if err := s.repo.UpdateLink(ctx, tx, link); err != nil {
			return err
		}
		if _, err := s.projects.BumpGraphVersion(ctx, tx, tenantID, projectID); err != nil {
			return err
		}

		pid := projectID
		rec := auditdomain.New(tenantID, &pid, "trace_link.accept",
			auditdomain.OutcomeSuccess, auditdomain.SeverityNotice,
			auditActor(actor),
			auditdomain.Target{Type: "TraceLink", ID: linkID.String(), ProjectID: pid.String()}).
			WithAttr("origin", string(link.Origin)).
			WithAttr("disposition_id", dispositionID)
		if err := s.audit.Append(ctx, tx, rec); err != nil {
			return err
		}
		if err := s.emitLink(ctx, tx, actor, link, "trace_link.accepted"); err != nil {
			return err
		}
		accepted = link
		return nil
	})
	return accepted, err
}

// RejectLink rejects a proposed link with a rationale.
func (s *Service) RejectLink(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	linkID types.LinkID, rationale string, actor authz.Principal) (*domain.TraceLink, error) {

	if err := s.authz.Require(actor, authz.LinkReject, authz.Resource{
		Type: "link", ID: linkID.String(), TenantID: tenantID, ProjectID: projectID.String(),
	}); err != nil {
		return nil, err
	}

	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: tenantID, ProjectID: &projectID, PrincipalID: actor.ID,
	})

	var rejected *domain.TraceLink
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		link, err := s.repo.GetLink(ctx, tenantID, projectID, linkID)
		if err != nil {
			return err
		}
		if err := link.Reject(rationale, actor.ID); err != nil {
			return err
		}
		if err := s.repo.UpdateLink(ctx, tx, link); err != nil {
			return err
		}

		pid := projectID
		rec := auditdomain.New(tenantID, &pid, "trace_link.reject",
			auditdomain.OutcomeSuccess, auditdomain.SeverityInfo,
			auditActor(actor),
			auditdomain.Target{Type: "TraceLink", ID: linkID.String(), ProjectID: pid.String()}).
			WithAttr("rationale", rationale)
		if err := s.audit.Append(ctx, tx, rec); err != nil {
			return err
		}
		if err := s.emitLink(ctx, tx, actor, link, "trace_link.rejected"); err != nil {
			return err
		}
		rejected = link
		return nil
	})
	return rejected, err
}

// ListLinks returns links matching a filter.
func (s *Service) ListLinks(ctx context.Context, f LinkFilter, actor authz.Principal) ([]*domain.TraceLink, error) {
	if err := s.authz.Require(actor, authz.LinkRead, authz.Resource{
		Type: "link", TenantID: f.TenantID, ProjectID: f.ProjectID.String(),
	}); err != nil {
		return nil, err
	}
	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: f.TenantID, ProjectID: &f.ProjectID, PrincipalID: actor.ID,
	})
	return s.repo.ListLinks(ctx, f)
}

// ---------------------------------------------------------------------------
// Traceability queries
// ---------------------------------------------------------------------------

// Upstream answers "what caused this?" — the walk from code toward the approved
// requirement and PRD that authorised it.
func (s *Service) Upstream(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	start types.ArtifactRef, filterTypes []types.ArtifactType, actor authz.Principal) (domain.Paths, error) {

	return s.traverse(ctx, tenantID, projectID, start, domain.Upstream, filterTypes, actor)
}

// Downstream answers "what implements this?" — the walk from a requirement
// toward code, tests and deployments.
func (s *Service) Downstream(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	start types.ArtifactRef, filterTypes []types.ArtifactType, actor authz.Principal) (domain.Paths, error) {

	return s.traverse(ctx, tenantID, projectID, start, domain.Downstream, filterTypes, actor)
}

func (s *Service) traverse(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	start types.ArtifactRef, dir domain.Direction, filterTypes []types.ArtifactType,
	actor authz.Principal) (domain.Paths, error) {

	if err := s.authz.Require(actor, authz.ArtifactRead, authz.Resource{
		Type: "artifact", TenantID: tenantID, ProjectID: projectID.String(),
	}); err != nil {
		return domain.Paths{}, err
	}
	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: tenantID, ProjectID: &projectID, PrincipalID: actor.ID,
	})

	started := obs.TraceIDFrom(ctx)
	_ = started

	return s.repo.Traverse(ctx, domain.TraverseSpec{
		TenantID: tenantID, ProjectID: projectID, Start: start,
		Direction: dir, ArtifactTypes: filterTypes, MaxDepth: s.maxDepth,
	})
}

// Impact computes the deterministic impact set of a change.
//
// No model participates: a hallucinated impact would either block correct work
// or hide a real risk, so severity comes from the edge type, the counterpart's
// approval state and the distance, all of which are facts in the graph.
func (s *Service) Impact(ctx context.Context, tenantID types.TenantID, projectID types.ProjectID,
	subject types.ArtifactRef, actor authz.Principal) (domain.ImpactSet, error) {

	paths, err := s.Downstream(ctx, tenantID, projectID, subject, nil, actor)
	if err != nil {
		return domain.ImpactSet{}, err
	}

	set := domain.ImpactSet{Subject: subject, Truncated: paths.Truncated}
	for _, p := range paths.Paths {
		if len(p.Hops) == 0 {
			continue
		}
		last := p.Hops[len(p.Hops)-1]
		severity, reason := domain.SeverityForHop(last.LinkType, p.Status, p.Depth)
		set.Impacted = append(set.Impacted, domain.Impacted{
			Target: p.Target, Type: p.Type, Status: p.Status,
			Distance: p.Depth, Severity: severity, Reason: reason, Path: p.Hops,
		})
		if severity.AtLeast(domain.ImpactHigh) {
			set.BlastRadius++
		}
	}
	return set, nil
}

func (s *Service) emitLink(ctx context.Context, tx db.Tx, actor authz.Principal,
	l *domain.TraceLink, eventType string) error {

	projectID := l.ProjectID
	return s.emitRaw(ctx, tx, actor, l.TenantID, &projectID,
		"TraceLink", l.LinkID.String(), 0, eventType, map[string]any{
			"link_id":    l.LinkID.String(),
			"from":       l.From.String(),
			"to":         l.To.String(),
			"link_type":  string(l.Type),
			"origin":     string(l.Origin),
			"confidence": l.Confidence,
			"status":     string(l.Status),
		})
}
