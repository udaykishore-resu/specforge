// Package domain is the canonical artifact model: the constitutional core of
// the platform.
//
// Every rule here exists because the platform's value depends on it:
//
//   - A sealed version is byte-immutable. There is no method that mutates one.
//   - content_hash is computed over the canonical form and verified on read.
//   - Approval requires evidence, and sealing supersedes the prior approved
//     version in the same operation.
//   - Version chains are gapless and start at 1.
package domain

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/fsm"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/types"
)

// Artifact lifecycle states, from docs/architecture/03-state-machines.md §1.
const (
	StatusDraft            fsm.State = "DRAFT"
	StatusAIReview         fsm.State = "AI_REVIEW"
	StatusUserReview       fsm.State = "USER_REVIEW"
	StatusChangesRequested fsm.State = "CHANGES_REQUESTED"
	StatusApproved         fsm.State = "APPROVED"
	StatusFrozen           fsm.State = "FROZEN"
	StatusSuperseded       fsm.State = "SUPERSEDED"
	StatusAbandoned        fsm.State = "ABANDONED"
)

// Artifact lifecycle events.
const (
	EventSubmitForAIReview fsm.Event = "submit_for_ai_review"
	EventAIReviewPassed    fsm.Event = "ai_review_passed"
	EventAIReviewBlocking  fsm.Event = "ai_review_findings_blocking"
	EventSubmitForReview   fsm.Event = "submit_for_review"
	EventRequestChanges    fsm.Event = "request_changes"
	EventApprove           fsm.Event = "approve"
	EventFreeze            fsm.Event = "freeze"
	EventSupersede         fsm.Event = "superseded_by"
	EventAbandon           fsm.Event = "abandon"
)

// sealedStates are byte-immutable once reached.
var sealedStates = map[fsm.State]bool{
	StatusApproved: true, StatusFrozen: true,
	StatusSuperseded: true, StatusAbandoned: true,
}

// IsSealed reports whether a state is immutable.
func IsSealed(s fsm.State) bool { return sealedStates[s] }

// Generator records what produced a version. Every version has one; there is no
// anonymous content in the graph.
type Generator struct {
	Kind types.GeneratorKind `json:"kind"`
	// Analyzer provenance.
	Analyzer        string `json:"analyzer,omitempty"`
	AnalyzerVersion string `json:"analyzer_version,omitempty"`
	// Inference provenance. All four are required together when Kind is
	// INFERENCE, so a model-produced artifact can always be traced to the exact
	// prompt, model and guardrail chain that produced it.
	PromptVersion         string              `json:"prompt_version,omitempty"`
	Model                 string              `json:"model,omitempty"`
	Provider              string              `json:"provider,omitempty"`
	Temperature           float64             `json:"temperature,omitempty"`
	GuardrailChainVersion string              `json:"guardrail_chain_version,omitempty"`
	InferenceID           string              `json:"inference_id,omitempty"`
	InputArtifacts        []types.ArtifactRef `json:"input_artifacts,omitempty"`
	// Import provenance.
	SourceSystem string `json:"source_system,omitempty"`
	SourceRef    string `json:"source_ref,omitempty"`
}

// Validate checks that the provenance is complete for its kind.
func (g Generator) Validate() error {
	const op = "artifact.Generator.Validate"

	if !g.Kind.Valid() {
		return errors.Invalid(op, "artifact.generator_kind_invalid",
			"Generator kind %q is not recognised.", g.Kind)
	}
	if g.Kind == types.GeneratedByInference {
		// Without these, an AI-produced artifact cannot be explained or
		// reproduced, which defeats the point of recording provenance at all.
		var missing []string
		if g.PromptVersion == "" {
			missing = append(missing, "prompt_version")
		}
		if g.Model == "" {
			missing = append(missing, "model")
		}
		if g.Provider == "" {
			missing = append(missing, "provider")
		}
		if g.GuardrailChainVersion == "" {
			missing = append(missing, "guardrail_chain_version")
		}
		if len(missing) > 0 {
			return errors.Invalid(op, "artifact.generator_incomplete",
				"AI-generated content must record %s.", strings.Join(missing, ", "))
		}
	}
	if g.Kind == types.GeneratedByAnalyzer && g.Analyzer == "" {
		return errors.Invalid(op, "artifact.generator_incomplete",
			"Analyzer-generated content must record the analyzer name.")
	}
	return nil
}

// ApprovalEvidence substantiates an approval.
type ApprovalEvidence struct {
	EvidenceID       string            `json:"evidence_id"`
	Digest           types.ContentHash `json:"digest"`
	MediaType        string            `json:"media_type"`
	StorageRef       string            `json:"storage_ref"`
	GateDecisions    []GateDecisionRef `json:"gate_decisions,omitempty"`
	PolicySetVersion string            `json:"policy_set_version,omitempty"`
	ApproverAuthTime time.Time         `json:"approver_auth_time,omitempty"`
	ApproverTokenID  string            `json:"approver_token_id,omitempty"`
}

// GateDecisionRef records a gate outcome that supported an approval.
type GateDecisionRef struct {
	Gate     string `json:"gate"`
	Decision string `json:"decision"`
	CaseID   string `json:"case_id,omitempty"`
}

// Valid reports whether the evidence is resolvable.
func (e ApprovalEvidence) Valid() bool {
	return e.EvidenceID != "" && e.Digest.Valid() && e.StorageRef != ""
}

// Artifact is the identity and history of a governed thing.
type Artifact struct {
	TenantID       types.TenantID
	ProjectID      types.ProjectID
	ID             types.ArtifactID
	Type           types.ArtifactType
	Title          string
	CurrentVersion int
	Status         fsm.State
	Labels         map[string]string
	CreatedBy      types.PrincipalID
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Version        int64
}

// Version is one immutable revision of an artifact.
type Version struct {
	TenantID      types.TenantID
	ProjectID     types.ProjectID
	ArtifactID    types.ArtifactID
	Version       int
	Type          types.ArtifactType
	Status        fsm.State
	ContentSchema string
	// Content is the canonical payload. Large payloads are externalized and
	// referenced by ContentRef instead.
	Content     json.RawMessage
	ContentRef  string
	ContentHash types.ContentHash

	ParentArtifact  *types.ArtifactRef
	SourceArtifact  *types.ArtifactRef
	PreviousVersion *int
	ChangeSummary   string
	Generator       Generator

	CreatedBy types.PrincipalID
	CreatedAt time.Time
	UpdatedAt time.Time

	ApprovedBy       *types.PrincipalID
	ApprovedAt       *time.Time
	ApprovalComment  string
	ApprovalEvidence *ApprovalEvidence
	SealedAt         *time.Time

	VersionNo int64
}

// InlineContentLimit is the payload size above which content is externalized to
// object storage. Below it, content stays queryable in the database.
const InlineContentLimit = 256 * 1024

// canonicalEnvelope is the projection the content hash covers.
//
// What it deliberately excludes is as important as what it includes:
//
//   - Status. Lifecycle state changes as a version moves through review, so
//     including it would change the hash at every transition. Excluding it gives
//     the property that matters: the hash of an approved version is the hash of
//     exactly the bytes that were reviewed, unchanged since the draft was
//     submitted. Status is guarded by the state machine, the database trigger
//     and the audit chain instead.
//   - Approval fields. Same reasoning: the approval attests to the content, so
//     the content hash must not depend on the attestation. The approval evidence
//     pins the hash, not the other way round.
//   - Trace links. Links are separate aggregates that may be added after a
//     version is sealed; including them would make the seal unstable.
type canonicalEnvelope struct {
	Schema          string             `json:"schema"`
	ArtifactID      string             `json:"artifact_id"`
	ArtifactType    string             `json:"artifact_type"`
	Version         int                `json:"version"`
	TenantID        string             `json:"tenant_id"`
	ProjectID       string             `json:"project_id"`
	ContentSchema   string             `json:"content_schema"`
	Content         json.RawMessage    `json:"content"`
	ContentRef      string             `json:"content_ref,omitempty"`
	ParentArtifact  *types.ArtifactRef `json:"parent_artifact,omitempty"`
	SourceArtifact  *types.ArtifactRef `json:"source_artifact,omitempty"`
	PreviousVersion *int               `json:"previous_version,omitempty"`
	ChangeSummary   string             `json:"change_summary"`
	CreatedBy       string             `json:"created_by"`
	CreatedAt       string             `json:"created_at"`
	Generator       Generator          `json:"generator"`
}

// CanonicalEnvelope returns the hashing projection.
func (v *Version) CanonicalEnvelope() canonicalEnvelope {
	return canonicalEnvelope{
		Schema:          "specforge.artifact.v1",
		ArtifactID:      v.ArtifactID.String(),
		ArtifactType:    string(v.Type),
		Version:         v.Version,
		TenantID:        v.TenantID.String(),
		ProjectID:       v.ProjectID.String(),
		ContentSchema:   v.ContentSchema,
		Content:         v.Content,
		ContentRef:      v.ContentRef,
		ParentArtifact:  v.ParentArtifact,
		SourceArtifact:  v.SourceArtifact,
		PreviousVersion: v.PreviousVersion,
		ChangeSummary:   v.ChangeSummary,
		CreatedBy:       v.CreatedBy.String(),
		CreatedAt:       v.CreatedAt.UTC().Format(time.RFC3339Nano),
		Generator:       v.Generator,
	}
}

// ComputeHash derives the content hash from the canonical envelope.
//
// The result is stable across the whole lifecycle of a version: a draft, the
// same draft in review, and the sealed approved version all hash identically.
// That stability is what lets an auditor confirm that the bytes approved are the
// bytes that were submitted for review.
func (v *Version) ComputeHash() (types.ContentHash, error) {
	return hash.Content(v.CanonicalEnvelope())
}

// Verify recomputes and compares the content hash.
func (v *Version) Verify() error {
	got, err := v.ComputeHash()
	if err != nil {
		return errors.Wrap(err, "artifact.Verify", errors.KindInternal,
			"artifact.hash_failed", "Could not compute the artifact hash.")
	}
	if !hash.Equal(got, v.ContentHash) {
		// Failing closed here is the whole point of content addressing: an
		// artifact that does not match its recorded hash is not served.
		return errors.Tampered("artifact.Verify", "artifact.integrity_violation",
			"Artifact %s version %d does not match its recorded content hash.",
			v.ArtifactID, v.Version).
			WithDetail("expected", v.ContentHash.Short()).
			WithDetail("actual", got.Short())
	}
	return nil
}

// Sealed reports whether the version is immutable.
func (v *Version) Sealed() bool { return IsSealed(v.Status) }

// Mutable reports whether the version's content may still be edited.
func (v *Version) Mutable() bool { return v.Status == StatusDraft }

// SetContent replaces a draft's payload and recomputes its hash.
func (v *Version) SetContent(content json.RawMessage) error {
	const op = "artifact.SetContent"

	if !v.Mutable() {
		return errors.Conflict(op, "artifact.sealed_immutable",
			"%s version %d is %s and cannot be modified. Create a new version instead.",
			v.ArtifactID, v.Version, v.Status)
	}
	if !json.Valid(content) {
		return errors.Invalid(op, "artifact.content_invalid", "The artifact content is not valid JSON.")
	}
	v.Content = content
	v.UpdatedAt = types.Now()

	h, err := v.ComputeHash()
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "artifact.hash_failed",
			"Could not compute the artifact hash.")
	}
	v.ContentHash = h
	return nil
}

// Validate checks a version's invariants.
func (v *Version) Validate() error {
	const op = "artifact.Validate"

	if v.TenantID.Empty() || v.ProjectID.Empty() {
		return errors.Invalid(op, "artifact.scope_required",
			"An artifact version must carry a tenant and a project.")
	}
	if _, err := types.ParseArtifactID(v.ArtifactID.String()); err != nil {
		return errors.Invalid(op, "artifact.id_invalid", "%s", err.Error())
	}
	if !v.Type.Valid() {
		return errors.Invalid(op, "artifact.type_invalid",
			"Artifact type %q is not recognised.", v.Type)
	}
	if v.Version < 1 {
		return errors.Invalid(op, "artifact.version_invalid", "Artifact versions start at 1.")
	}
	if (v.Version == 1) != (v.PreviousVersion == nil) {
		return errors.Invalid(op, "artifact.chain_invalid",
			"Version 1 must have no predecessor, and later versions must declare one.")
	}
	if v.PreviousVersion != nil && *v.PreviousVersion != v.Version-1 {
		return errors.Invalid(op, "artifact.chain_gap",
			"Version %d must follow version %d without a gap.", v.Version, v.Version-1)
	}
	if v.ContentSchema == "" {
		return errors.Invalid(op, "artifact.content_schema_required",
			"An artifact version must declare its content schema.")
	}
	if len(v.Content) == 0 && v.ContentRef == "" {
		return errors.Invalid(op, "artifact.content_required",
			"An artifact version must carry content or a content reference.")
	}
	if len(v.Content) > InlineContentLimit {
		return errors.Invalid(op, "artifact.content_too_large",
			"Inline content exceeds %d bytes; it must be stored by reference.", InlineContentLimit)
	}
	if err := v.Generator.Validate(); err != nil {
		return err
	}
	if v.Status == StatusApproved {
		if v.ApprovedBy == nil || v.ApprovedAt == nil {
			return errors.Invalid(op, "artifact.approval_incomplete",
				"An approved version must record its approver and approval time.")
		}
		if strings.TrimSpace(v.ApprovalComment) == "" {
			return errors.Invalid(op, "artifact.approval_comment_required",
				"An approval comment is required; it is the reviewer's statement of what they verified.")
		}
		if v.ApprovalEvidence == nil || !v.ApprovalEvidence.Valid() {
			return errors.Invalid(op, "artifact.approval_evidence_required",
				"An approved version must reference resolvable approval evidence.")
		}
	}
	return nil
}

// NewVersion constructs the first version of a new artifact.
func NewVersion(tenantID types.TenantID, projectID types.ProjectID,
	artifactID types.ArtifactID, typ types.ArtifactType,
	contentSchema string, content json.RawMessage,
	gen Generator, by types.PrincipalID) (*Version, error) {

	const op = "artifact.NewVersion"

	if contentSchema == "" {
		contentSchema = typ.DefaultContentSchema()
	}
	if len(content) == 0 {
		content = json.RawMessage(`{}`)
	}
	if !json.Valid(content) {
		return nil, errors.Invalid(op, "artifact.content_invalid",
			"The artifact content is not valid JSON.")
	}

	now := types.Now()
	v := &Version{
		TenantID: tenantID, ProjectID: projectID, ArtifactID: artifactID,
		Version: 1, Type: typ, Status: StatusDraft,
		ContentSchema: contentSchema, Content: content,
		Generator: gen, CreatedBy: by, CreatedAt: now, UpdatedAt: now, VersionNo: 1,
	}
	if err := v.Validate(); err != nil {
		return nil, err
	}
	h, err := v.ComputeHash()
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindInternal, "artifact.hash_failed",
			"Could not compute the artifact hash.")
	}
	v.ContentHash = h
	return v, nil
}

// Revise creates the next draft version from an existing one.
//
// This is the only way an approved artifact ever "changes": a new version is
// created from it, leaving the approved version untouched.
func (v *Version) Revise(changeSummary string, by types.PrincipalID, gen Generator) (*Version, error) {
	const op = "artifact.Revise"

	if strings.TrimSpace(changeSummary) == "" {
		return nil, errors.Invalid(op, "artifact.change_summary_required",
			"A change summary is required so reviewers can see what changed and why.")
	}

	prev := v.Version
	now := types.Now()
	next := &Version{
		TenantID: v.TenantID, ProjectID: v.ProjectID, ArtifactID: v.ArtifactID,
		Version: v.Version + 1, Type: v.Type, Status: StatusDraft,
		ContentSchema: v.ContentSchema, Content: append(json.RawMessage(nil), v.Content...),
		ContentRef:     v.ContentRef,
		ParentArtifact: v.ParentArtifact, SourceArtifact: v.SourceArtifact,
		PreviousVersion: &prev, ChangeSummary: changeSummary,
		Generator: gen, CreatedBy: by, CreatedAt: now, UpdatedAt: now, VersionNo: 1,
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	h, err := next.ComputeHash()
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindInternal, "artifact.hash_failed",
			"Could not compute the artifact hash.")
	}
	next.ContentHash = h
	return next, nil
}

// SealApproval records the approval fields and recomputes the hash.
//
// After this returns, the version is byte-immutable: the repository has no
// update path for it and the database trigger refuses one.
//
// The approval instant is passed in rather than read from the clock here. The
// same instant is written into the approval evidence document, and evidence
// whose timestamp disagrees with the row it attests to is evidence an auditor
// is entitled to reject.
func (v *Version) SealApproval(approver types.PrincipalID, comment string,
	evidence ApprovalEvidence, at time.Time) error {
	const op = "artifact.SealApproval"

	if strings.TrimSpace(comment) == "" {
		return errors.Invalid(op, "artifact.approval_comment_required",
			"An approval comment is required; it is the reviewer's statement of what they verified.")
	}
	if !evidence.Valid() {
		return errors.Invalid(op, "artifact.approval_evidence_required",
			"Approval evidence must be complete and resolvable.")
	}

	// Sealing must not change the content hash. Recomputing and comparing here
	// turns that expectation into an assertion: if a future change to the
	// canonical envelope ever made the hash depend on approval state, this would
	// fail loudly at the seal rather than silently at the next read.
	before := v.ContentHash

	now := types.NormalizeTime(at)
	if now.IsZero() {
		return errors.Invalid(op, "artifact.approval_time_required",
			"An approval instant is required.")
	}
	v.Status = StatusApproved
	v.ApprovedBy = &approver
	v.ApprovedAt = &now
	v.ApprovalComment = comment
	v.ApprovalEvidence = &evidence
	v.SealedAt = &now
	v.UpdatedAt = now

	after, err := v.ComputeHash()
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "artifact.hash_failed",
			"Could not compute the artifact hash.")
	}
	if before != "" && after != before {
		return errors.Internal(op, "artifact.hash_unstable",
			"Sealing changed the content hash, which must never happen.")
	}
	v.ContentHash = after
	return v.Validate()
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

// requireContent refuses to advance a version with no payload.
func requireContent(_ context.Context, v *Version) error {
	if len(v.Content) == 0 && v.ContentRef == "" {
		return errors.Invalid("artifact.requireContent", "artifact.content_required",
			"The artifact has no content to review.")
	}
	return nil
}

// requireSchema refuses to advance a version that declares no payload schema,
// since nothing downstream can validate it.
func requireSchema(_ context.Context, v *Version) error {
	if v.ContentSchema == "" {
		return errors.Invalid("artifact.requireSchema", "artifact.content_schema_required",
			"The artifact declares no content schema.")
	}
	return nil
}

// Machine is the artifact lifecycle, shared by every artifact type.
var Machine = fsm.New(fsm.Definition[*Version]{
	Name:    "artifact",
	Initial: StatusDraft,
	States: []fsm.State{
		StatusDraft, StatusAIReview, StatusUserReview, StatusChangesRequested,
		StatusApproved, StatusFrozen, StatusSuperseded, StatusAbandoned,
	},
	Terminal: []fsm.State{StatusSuperseded, StatusAbandoned},
	Transitions: []fsm.Transition[*Version]{
		{
			From: []fsm.State{StatusDraft}, Event: EventSubmitForAIReview, To: StatusAIReview,
			Permission: "artifact:submit",
			Guards:     []fsm.Guard[*Version]{requireContent, requireSchema},
			EmitEvent:  "artifact.submitted_for_ai_review", AuditAction: "artifact.submit_ai_review",
			Description: "AI review is advisory; its findings never approve anything.",
		},
		{
			From: []fsm.State{StatusAIReview}, Event: EventAIReviewPassed, To: StatusUserReview,
			EmitEvent: "artifact.ai_review_passed", AuditAction: "artifact.ai_review_passed",
		},
		{
			From: []fsm.State{StatusAIReview}, Event: EventAIReviewBlocking, To: StatusChangesRequested,
			EmitEvent: "artifact.changes_requested", AuditAction: "artifact.ai_review_blocking",
		},
		{
			From: []fsm.State{StatusDraft}, Event: EventSubmitForReview, To: StatusUserReview,
			Permission: "artifact:submit",
			Guards:     []fsm.Guard[*Version]{requireContent, requireSchema},
			EmitEvent:  "artifact.submitted_for_review", AuditAction: "artifact.submit",
		},
		{
			From: []fsm.State{StatusUserReview}, Event: EventRequestChanges, To: StatusChangesRequested,
			Permission: "artifact:review",
			EmitEvent:  "artifact.changes_requested", AuditAction: "artifact.request_changes",
		},
		{
			From: []fsm.State{StatusUserReview}, Event: EventApprove, To: StatusApproved,
			Permission: "artifact:approve",
			Guards:     []fsm.Guard[*Version]{requireContent, requireSchema},
			EmitEvent:  "artifact.approved", AuditAction: "artifact.approve",
			Description: "Seals the version, writes evidence and supersedes the prior approval.",
		},
		{
			From: []fsm.State{StatusApproved}, Event: EventFreeze, To: StatusFrozen,
			Permission: "artifact:freeze",
			EmitEvent:  "artifact.frozen", AuditAction: "artifact.freeze",
			Description: "Pins a baseline; new versions require Design Authority release.",
		},
		{
			From: []fsm.State{StatusApproved, StatusFrozen}, Event: EventSupersede, To: StatusSuperseded,
			EmitEvent: "artifact.superseded", AuditAction: "artifact.supersede",
		},
		{
			From: []fsm.State{StatusDraft, StatusChangesRequested}, Event: EventAbandon, To: StatusAbandoned,
			Permission: "artifact:delete",
			EmitEvent:  "artifact.abandoned", AuditAction: "artifact.abandon",
		},
	},
})
