// Package authz implements the authorization model.
//
// The design is RBAC at the coarse layer with ABAC refinements for a small,
// explicit set of sensitive actions. That split keeps the hot path a bitset
// comparison while still expressing rules like "the approver may not be the sole
// author" and "only Design Authority members may grant exceptions".
//
// Deny always wins, and the absence of a grant is a deny.
package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Permission is a dense identifier for a "<resource>:<action>" capability.
type Permission uint16

// The permission namespace. Adding a permission here and to permissionNames is
// the only way to create one; routes reference these constants, and the route
// lint fails any route that declares none.
const (
	permInvalid Permission = iota

	// Tenancy
	TenantRead
	TenantCreate
	TenantUpdate
	TenantSuspend
	TenantPurge

	// Projects
	ProjectCreate
	ProjectRead
	ProjectUpdate
	ProjectArchive

	// Identity
	PrincipalRead
	PrincipalInvite
	RoleAssign
	APIKeyCreate
	APIKeyRevoke
	IdPMappingRead
	IdPMappingUpdate

	// Artifacts
	ArtifactCreate
	ArtifactRead
	ArtifactEdit
	ArtifactSubmit
	ArtifactReview
	ArtifactApprove
	ArtifactFreeze
	ArtifactDelete

	// Trace links
	LinkCreate
	LinkRead
	LinkAccept
	LinkReject

	// PRD Studio
	PRDDiscovery
	PRDUpload
	PRDApprove

	// Specifications and models
	SpecGenerate
	SpecApprove
	ModelGenerate
	ModelEdit

	// Code and repositories
	CodeGenerate
	CodeRead
	RepoConnect
	RepoIngest

	// Synchronization
	SyncRun
	ProposalSubmit
	ProposalApprove

	// Governance
	GateEvaluate
	PolicyRead
	PolicyUpdate
	ExceptionRequest
	ExceptionGrant
	DispositionRecord
	DesignAuthorityDecide

	// Delivery
	PipelineRead
	PipelineTrigger
	PipelineApprove
	DeploymentRead
	DeploymentApprove
	DeploymentRollback

	// Runtime
	RuntimeRead
	IncidentAck
	IncidentManage
	EscalationManage

	// Compliance
	ScanRun
	FindingRead
	FindingSuppress

	// AI platform
	AIInvoke
	AIConfig
	PromptRead
	PromptPublish
	GuardrailConfig

	// Audit
	AuditRead
	AuditExport

	permMax
)

var permissionNames = map[Permission]string{
	TenantRead:            "tenant:read",
	TenantCreate:          "tenant:create",
	TenantUpdate:          "tenant:update",
	TenantSuspend:         "tenant:suspend",
	TenantPurge:           "tenant:purge",
	ProjectCreate:         "project:create",
	ProjectRead:           "project:read",
	ProjectUpdate:         "project:update",
	ProjectArchive:        "project:archive",
	PrincipalRead:         "principal:read",
	PrincipalInvite:       "principal:invite",
	RoleAssign:            "role:assign",
	APIKeyCreate:          "apikey:create",
	APIKeyRevoke:          "apikey:revoke",
	IdPMappingRead:        "idpmapping:read",
	IdPMappingUpdate:      "idpmapping:update",
	ArtifactCreate:        "artifact:create",
	ArtifactRead:          "artifact:read",
	ArtifactEdit:          "artifact:edit",
	ArtifactSubmit:        "artifact:submit",
	ArtifactReview:        "artifact:review",
	ArtifactApprove:       "artifact:approve",
	ArtifactFreeze:        "artifact:freeze",
	ArtifactDelete:        "artifact:delete",
	LinkCreate:            "link:create",
	LinkRead:              "link:read",
	LinkAccept:            "link:accept",
	LinkReject:            "link:reject",
	PRDDiscovery:          "prd:discovery",
	PRDUpload:             "prd:upload",
	PRDApprove:            "prd:approve",
	SpecGenerate:          "spec:generate",
	SpecApprove:           "spec:approve",
	ModelGenerate:         "model:generate",
	ModelEdit:             "model:edit",
	CodeGenerate:          "code:generate",
	CodeRead:              "code:read",
	RepoConnect:           "repo:connect",
	RepoIngest:            "repo:ingest",
	SyncRun:               "sync:run",
	ProposalSubmit:        "proposal:submit",
	ProposalApprove:       "proposal:approve",
	GateEvaluate:          "gate:evaluate",
	PolicyRead:            "policy:read",
	PolicyUpdate:          "policy:update",
	ExceptionRequest:      "exception:request",
	ExceptionGrant:        "exception:grant",
	DispositionRecord:     "disposition:record",
	DesignAuthorityDecide: "designauthority:decide",
	PipelineRead:          "pipeline:read",
	PipelineTrigger:       "pipeline:trigger",
	PipelineApprove:       "pipeline:approve",
	DeploymentRead:        "deployment:read",
	DeploymentApprove:     "deployment:approve",
	DeploymentRollback:    "deployment:rollback",
	RuntimeRead:           "runtime:read",
	IncidentAck:           "incident:ack",
	IncidentManage:        "incident:manage",
	EscalationManage:      "escalation:manage",
	ScanRun:               "scan:run",
	FindingRead:           "finding:read",
	FindingSuppress:       "finding:suppress",
	AIInvoke:              "ai:invoke",
	AIConfig:              "ai:config",
	PromptRead:            "prompt:read",
	PromptPublish:         "prompt:publish",
	GuardrailConfig:       "guardrail:config",
	AuditRead:             "audit:read",
	AuditExport:           "audit:export",
}

var permissionByName = func() map[string]Permission {
	m := make(map[string]Permission, len(permissionNames))
	for p, n := range permissionNames {
		m[n] = p
	}
	return m
}()

func (p Permission) String() string {
	if n, ok := permissionNames[p]; ok {
		return n
	}
	return fmt.Sprintf("permission(%d)", uint16(p))
}

// ParsePermission resolves a permission name.
func ParsePermission(s string) (Permission, error) {
	p, ok := permissionByName[strings.TrimSpace(s)]
	if !ok {
		return permInvalid, fmt.Errorf("unknown permission %q", s)
	}
	return p, nil
}

// AllPermissions returns every permission name, sorted. Used by the RBAC config
// generator and by the API's /auth/me response.
func AllPermissions() []string {
	out := make([]string, 0, len(permissionNames))
	for _, n := range permissionNames {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Permission sets
// ---------------------------------------------------------------------------

const setWords = (int(permMax) + 63) / 64

// Set is a fixed-size permission bitset. Membership tests are a single word
// comparison, which keeps the authorization hot path off the allocator.
type Set struct {
	bits [setWords]uint64
}

// NewSet builds a set from permissions.
func NewSet(perms ...Permission) Set {
	var s Set
	for _, p := range perms {
		s.add(p)
	}
	return s
}

func (s *Set) add(p Permission) {
	if p == permInvalid || p >= permMax {
		return
	}
	s.bits[p/64] |= 1 << (p % 64)
}

// Has reports whether the set contains p.
func (s Set) Has(p Permission) bool {
	if p == permInvalid || p >= permMax {
		return false
	}
	return s.bits[p/64]&(1<<(p%64)) != 0
}

// HasAll reports whether the set contains every permission listed.
func (s Set) HasAll(ps ...Permission) bool {
	for _, p := range ps {
		if !s.Has(p) {
			return false
		}
	}
	return true
}

// HasAny reports whether the set contains at least one of the permissions.
func (s Set) HasAny(ps ...Permission) bool {
	for _, p := range ps {
		if s.Has(p) {
			return true
		}
	}
	return false
}

// Union returns the combination of two sets. Role grants are additive, so a
// principal's effective permissions are the union of every grant in scope.
func (s Set) Union(other Set) Set {
	var out Set
	for i := range s.bits {
		out.bits[i] = s.bits[i] | other.bits[i]
	}
	return out
}

// Intersect returns the permissions present in both sets. Used to clamp a
// delegated system principal to the originating user's permissions.
func (s Set) Intersect(other Set) Set {
	var out Set
	for i := range s.bits {
		out.bits[i] = s.bits[i] & other.bits[i]
	}
	return out
}

// Without removes the permissions in other.
func (s Set) Without(other Set) Set {
	var out Set
	for i := range s.bits {
		out.bits[i] = s.bits[i] &^ other.bits[i]
	}
	return out
}

// Empty reports whether the set grants nothing.
func (s Set) Empty() bool {
	for _, w := range s.bits {
		if w != 0 {
			return false
		}
	}
	return true
}

// Names lists the permissions in the set, sorted.
func (s Set) Names() []string {
	var out []string
	for p := permInvalid + 1; p < permMax; p++ {
		if s.Has(p) {
			out = append(out, p.String())
		}
	}
	sort.Strings(out)
	return out
}

// FromNames builds a set from permission names, reporting any unknown name.
// Unknown names are an error rather than silently ignored: a typo in a policy
// must not quietly reduce someone's access, or quietly fail to.
func FromNames(names []string) (Set, error) {
	var s Set
	var unknown []string
	for _, n := range names {
		p, err := ParsePermission(n)
		if err != nil {
			unknown = append(unknown, n)
			continue
		}
		s.add(p)
	}
	if len(unknown) > 0 {
		return Set{}, fmt.Errorf("unknown permissions: %s", strings.Join(unknown, ", "))
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// Sensitive actions
// ---------------------------------------------------------------------------

// approvalPermissions are the capabilities a service account may never hold
// (SoD-6) and which always require step-up authentication.
var approvalPermissions = NewSet(
	ArtifactApprove, PRDApprove, SpecApprove, ProposalApprove,
	ExceptionGrant, DesignAuthorityDecide, DeploymentApprove,
	PipelineApprove, FindingSuppress, PolicyUpdate, TenantPurge,
	APIKeyCreate, RoleAssign, PromptPublish, GuardrailConfig,
)

// IsApprovalPermission reports whether p carries approval authority.
func IsApprovalPermission(p Permission) bool { return approvalPermissions.Has(p) }

// ApprovalPermissionNames lists the approval permissions, for the database
// CHECK constraint on api_keys and for documentation.
func ApprovalPermissionNames() []string { return approvalPermissions.Names() }

// RequiresStepUp reports whether p demands a recent MFA authentication.
func RequiresStepUp(p Permission) bool { return approvalPermissions.Has(p) }
