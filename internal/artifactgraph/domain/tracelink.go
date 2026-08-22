package domain

import (
	"encoding/json"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/types"
)

// TraceLink is a typed, directed edge between two artifact versions.
//
// Links are first-class rows rather than inferred joins because traceability
// has to be defensible: an auditor needs to see who asserted a relationship,
// how confident they were, and whether a governance decision accepted it.
type TraceLink struct {
	TenantID   types.TenantID
	ProjectID  types.ProjectID
	LinkID     types.LinkID
	From       types.ArtifactRef
	To         types.ArtifactRef
	Type       types.LinkType
	Origin     types.LinkOrigin
	Confidence float64
	Status     types.LinkStatus
	Rationale  string
	Evidence   json.RawMessage
	// DispositionID is mandatory before an LLM-proposed link may be accepted.
	DispositionID *string
	CreatedBy     types.PrincipalID
	CreatedAt     time.Time
	UpdatedAt     time.Time
	VersionNo     int64
}

// NewTraceLink constructs a link and applies the default status for its origin.
func NewTraceLink(tenantID types.TenantID, projectID types.ProjectID, linkID types.LinkID,
	from, to types.ArtifactRef, linkType types.LinkType, origin types.LinkOrigin,
	confidence float64, by types.PrincipalID) (*TraceLink, error) {

	const op = "artifact.NewTraceLink"

	if !linkType.Valid() {
		return nil, errors.Invalid(op, "link.type_invalid",
			"Link type %q is not recognised.", linkType)
	}
	if !origin.Valid() {
		return nil, errors.Invalid(op, "link.origin_invalid",
			"Link origin %q is not recognised.", origin)
	}
	if confidence < 0 || confidence > 1 {
		return nil, errors.Invalid(op, "link.confidence_invalid",
			"Confidence must be between 0 and 1.")
	}
	if from.Zero() || to.Zero() {
		return nil, errors.Invalid(op, "link.endpoints_required",
			"A trace link needs both endpoints.")
	}
	if from.ArtifactID == to.ArtifactID && from.Version == to.Version {
		return nil, errors.Invalid(op, "link.self_reference",
			"An artifact version cannot link to itself.")
	}

	now := types.Now()
	l := &TraceLink{
		TenantID: tenantID, ProjectID: projectID, LinkID: linkID,
		From: from, To: to, Type: linkType, Origin: origin,
		Confidence: confidence, Status: defaultStatusFor(origin, confidence),
		CreatedBy: by, CreatedAt: now, UpdatedAt: now, VersionNo: 1,
	}
	return l, nil
}

// defaultStatusFor decides whether a new link starts accepted or proposed.
//
// Human assertions and exact analyzer derivations are accepted immediately.
// Anything a model inferred, and anything an analyzer guessed below the exact
// threshold, starts as a proposal.
func defaultStatusFor(origin types.LinkOrigin, confidence float64) types.LinkStatus {
	switch origin {
	case types.OriginHuman:
		return types.LinkAccepted
	case types.OriginAnalyzer:
		if confidence >= 1.0 {
			return types.LinkAccepted
		}
		return types.LinkProposed
	default:
		return types.LinkProposed
	}
}

// Accept marks a link accepted.
//
// An LLM-proposed link requires a governance disposition. This is the rule
// "AI proposes, governance validates" at its smallest scale, and it is enforced
// here, in the repository, and by a database CHECK constraint.
func (l *TraceLink) Accept(dispositionID string, by types.PrincipalID) error {
	const op = "artifact.AcceptLink"

	if l.Status == types.LinkAccepted {
		return nil
	}
	if l.Status == types.LinkRejected {
		return errors.Conflict(op, "link.rejected",
			"This link was rejected; create a new one rather than reviving it.")
	}
	if l.Origin.RequiresDisposition() && dispositionID == "" {
		return errors.Precondition(op, "link.disposition_required",
			"An AI-proposed link cannot be accepted without a recorded governance decision.")
	}
	l.Status = types.LinkAccepted
	if dispositionID != "" {
		l.DispositionID = &dispositionID
	}
	l.UpdatedAt = types.Now()
	return nil
}

// Reject marks a link rejected with a rationale.
func (l *TraceLink) Reject(rationale string, by types.PrincipalID) error {
	if rationale == "" {
		return errors.Invalid("artifact.RejectLink", "link.rationale_required",
			"A rejection rationale is required.")
	}
	l.Status = types.LinkRejected
	l.Rationale = rationale
	l.UpdatedAt = types.Now()
	return nil
}

// MarkStale flags a link whose endpoint has been superseded.
func (l *TraceLink) MarkStale(reason string) {
	l.Status = types.LinkStale
	l.Rationale = reason
	l.UpdatedAt = types.Now()
}

// Active reports whether the link participates in traversal.
func (l *TraceLink) Active() bool { return l.Status == types.LinkAccepted }

// ---------------------------------------------------------------------------
// Traversal
// ---------------------------------------------------------------------------

// Direction selects which way a traversal walks the graph.
type Direction string

const (
	// Upstream walks toward causes: code to specification to requirement to PRD.
	Upstream Direction = "UPSTREAM"
	// Downstream walks toward consequences: requirement to code to deployment.
	Downstream Direction = "DOWNSTREAM"
)

// TraverseSpec bounds a graph walk.
type TraverseSpec struct {
	TenantID  types.TenantID
	ProjectID types.ProjectID
	Start     types.ArtifactRef
	Direction Direction
	// LinkTypes restricts which edges are followed. Empty means all.
	LinkTypes []types.LinkType
	// ArtifactTypes restricts which nodes are returned. Empty means all.
	ArtifactTypes []types.ArtifactType
	// MaxDepth bounds the walk. Cycles are handled by a visited set, but a depth
	// bound also keeps a pathological graph from producing an enormous response.
	MaxDepth int
	// IncludeProposed follows links that governance has not accepted. Off by
	// default: a traceability answer should not rest on an unaccepted claim.
	IncludeProposed bool
}

// Hop is one edge in a traversal path.
type Hop struct {
	From       types.ArtifactRef `json:"from"`
	To         types.ArtifactRef `json:"to"`
	LinkType   types.LinkType    `json:"link_type"`
	Origin     types.LinkOrigin  `json:"origin"`
	Confidence float64           `json:"confidence"`
	Status     types.LinkStatus  `json:"status"`
}

// Path is a route from the traversal's origin to a reachable artifact.
type Path struct {
	Target types.ArtifactRef  `json:"target"`
	Type   types.ArtifactType `json:"artifact_type"`
	Title  string             `json:"title,omitempty"`
	Status string             `json:"status,omitempty"`
	Hops   []Hop              `json:"hops"`
	Depth  int                `json:"depth"`
}

// Paths is the result of a traversal.
type Paths struct {
	Start     types.ArtifactRef `json:"start"`
	Direction Direction         `json:"direction"`
	Paths     []Path            `json:"paths"`
	// Truncated reports that the depth bound stopped the walk before exhausting
	// the graph, so a caller knows the answer is partial rather than complete.
	Truncated bool `json:"truncated"`
}

// ImpactSeverity grades how strongly a change propagates along an edge.
type ImpactSeverity string

const (
	ImpactInfo     ImpactSeverity = "INFO"
	ImpactLow      ImpactSeverity = "LOW"
	ImpactMedium   ImpactSeverity = "MEDIUM"
	ImpactHigh     ImpactSeverity = "HIGH"
	ImpactCritical ImpactSeverity = "CRITICAL"
)

// Impacted is one artifact affected by a change.
type Impacted struct {
	Target   types.ArtifactRef  `json:"target"`
	Type     types.ArtifactType `json:"artifact_type"`
	Status   string             `json:"status"`
	Distance int                `json:"distance"`
	Severity ImpactSeverity     `json:"severity"`
	Reason   string             `json:"reason"`
	Path     []Hop              `json:"path"`
}

// ImpactSet is the result of an impact analysis.
type ImpactSet struct {
	Subject   types.ArtifactRef `json:"subject"`
	Impacted  []Impacted        `json:"impacted"`
	Truncated bool              `json:"truncated"`
	// BlastRadius is the count of impacted artifacts at HIGH or above, which is
	// the number a reviewer actually wants to see first.
	BlastRadius int `json:"blast_radius"`
}

// SeverityForHop grades the impact of traversing one edge.
//
// The grading is deterministic and depends only on the edge type, the target's
// approval state and the distance. No model participates: a hallucinated impact
// severity would either block correct work or hide a real risk.
func SeverityForHop(linkType types.LinkType, targetStatus string, distance int) (ImpactSeverity, string) {
	approved := targetStatus == string(StatusApproved) || targetStatus == string(StatusFrozen)

	base := ImpactMedium
	reason := "the artifact is linked to the change"

	switch linkType {
	case types.LinkSatisfies, types.LinkImplements:
		base = ImpactHigh
		reason = "the artifact directly implements or satisfies the changed artifact"
	case types.LinkDerivedFrom:
		base = ImpactHigh
		reason = "the artifact was derived from the changed artifact"
	case types.LinkVerifies:
		base = ImpactMedium
		reason = "the artifact verifies behaviour that may have changed"
	case types.LinkRepresentedBy:
		base = ImpactMedium
		reason = "the artifact models the same behaviour in another form"
	case types.LinkDependsOn, types.LinkContains:
		base = ImpactLow
		reason = "the artifact depends on or contains the changed artifact"
	case types.LinkConflictsWith:
		base = ImpactCritical
		reason = "the artifact is recorded as contradicting the changed artifact"
	case types.LinkEvidences, types.LinkGoverns:
		base = ImpactLow
		reason = "the artifact governs or evidences the changed artifact"
	}

	// An approved counterpart raises the stakes: changing something an approved
	// artifact depends on is a governance event, not a routine edit.
	if approved && base != ImpactCritical {
		base = raise(base)
		reason += "; the affected artifact is approved"
	}
	// Impact decays with distance, but never below LOW for an approved artifact.
	for i := 1; i < distance; i++ {
		if approved && base == ImpactLow {
			break
		}
		base = lower(base)
	}
	return base, reason
}

func raise(s ImpactSeverity) ImpactSeverity {
	switch s {
	case ImpactInfo:
		return ImpactLow
	case ImpactLow:
		return ImpactMedium
	case ImpactMedium:
		return ImpactHigh
	default:
		return ImpactCritical
	}
}

func lower(s ImpactSeverity) ImpactSeverity {
	switch s {
	case ImpactCritical:
		return ImpactHigh
	case ImpactHigh:
		return ImpactMedium
	case ImpactMedium:
		return ImpactLow
	default:
		return ImpactInfo
	}
}

// AtLeast reports whether s is at or above the threshold.
func (s ImpactSeverity) AtLeast(threshold ImpactSeverity) bool {
	return severityRank(s) >= severityRank(threshold)
}

func severityRank(s ImpactSeverity) int {
	switch s {
	case ImpactCritical:
		return 5
	case ImpactHigh:
		return 4
	case ImpactMedium:
		return 3
	case ImpactLow:
		return 2
	default:
		return 1
	}
}
