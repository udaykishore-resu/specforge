package server

import (
	"context"
	"strings"

	artifactapp "github.com/specforge/specforge/internal/artifactgraph/app"
	artifactdomain "github.com/specforge/specforge/internal/artifactgraph/domain"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/types"
)

// baselineGates is the Phase 1 governance gate evaluator.
//
// Phase 10 replaces this with the policy engine described in
// docs/architecture/15-governance-architecture.md. It exists now, wired into the
// approval path, for two reasons: the approval flow already routes through
// governance and will not need restructuring, and the baseline rules it does
// enforce are the ones that must never be absent — an approved artifact must
// have content, must declare a schema, and must not derive from an unapproved
// parent.
//
// The evaluator is deterministic and never calls a model.
type baselineGates struct {
	repo artifactapp.Repository
}

var _ artifactapp.GateEvaluator = (*baselineGates)(nil)

func newBaselineGates(repo artifactapp.Repository) *baselineGates {
	return &baselineGates{repo: repo}
}

// gateFor maps an artifact type onto the gate that governs it.
func gateFor(t types.ArtifactType) string {
	switch t {
	case types.ArtifactPRD, types.ArtifactRequirement:
		return "PRD_GATE"
	case types.ArtifactArchitecture:
		return "ARCHITECTURE_GATE"
	case types.ArtifactCodeUnit, types.ArtifactAPIContract:
		return "CODE_GOVERNANCE_GATE"
	case types.ArtifactTestCase:
		return "TESTING_GATE"
	case types.ArtifactDeployment, types.ArtifactPipelineDef:
		return "DEPLOYMENT_GATE"
	case types.ArtifactPolicy:
		return "COMPLIANCE_GATE"
	default:
		return "SPECIFICATION_GATE"
	}
}

// Evaluate runs the baseline rules.
//
// A blocking rule returns an error, which stops the approval before any
// evidence is written. That ordering matters: a blocked attempt should leave no
// trace of an approval having been contemplated.
func (g *baselineGates) Evaluate(ctx context.Context, subject artifactapp.GateSubject) ([]artifactdomain.GateDecisionRef, error) {
	const op = "governance.Evaluate"

	gate := gateFor(subject.ArtifactType)

	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: subject.TenantID, ProjectID: &subject.ProjectID, PrincipalID: subject.Actor,
	})

	v, err := g.repo.GetVersion(ctx, subject.TenantID, subject.ProjectID,
		subject.ArtifactID, subject.Version)
	if err != nil {
		return nil, err
	}

	// Rule GOV-001: an artifact cannot be approved with no content.
	if len(v.Content) == 0 && v.ContentRef == "" {
		return nil, errors.Precondition(op, "gate.blocked",
			"%s blocked approval: the artifact has no content.", gate).
			WithDetail("gate", gate).
			WithDetail("rule", "GOV-001")
	}
	// Rule GOV-002: an artifact cannot be approved without declaring the schema
	// its content is validated against.
	if strings.TrimSpace(v.ContentSchema) == "" {
		return nil, errors.Precondition(op, "gate.blocked",
			"%s blocked approval: the artifact declares no content schema.", gate).
			WithDetail("gate", gate).
			WithDetail("rule", "GOV-002")
	}
	// Rule GOV-003: a derived artifact cannot be approved while the artifact it
	// derives from is unapproved. Approving a specification whose PRD is still a
	// draft would create evidence that points at nothing settled.
	if v.SourceArtifact != nil {
		source, err := g.repo.GetVersion(ctx, subject.TenantID, subject.ProjectID,
			v.SourceArtifact.ArtifactID, v.SourceArtifact.Version)
		if err == nil {
			if source.Status != artifactdomain.StatusApproved &&
				source.Status != artifactdomain.StatusFrozen &&
				source.Status != artifactdomain.StatusSuperseded {
				return nil, errors.Precondition(op, "gate.blocked",
					"%s blocked approval: the source artifact %s is %s, not approved.",
					gate, v.SourceArtifact.ArtifactID, source.Status).
					WithDetail("gate", gate).
					WithDetail("rule", "GOV-003").
					WithDetail("source_artifact", v.SourceArtifact.String())
			}
		}
	}

	return []artifactdomain.GateDecisionRef{{
		Gate:     gate,
		Decision: "ALLOW",
		CaseID:   "",
	}}, nil
}
