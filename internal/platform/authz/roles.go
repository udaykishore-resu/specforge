package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Role is a named bundle of permissions.
type Role string

const (
	RolePlatformAdmin   Role = "platform_admin"
	RoleTenantAdmin     Role = "tenant_admin"
	RoleProductOwner    Role = "product_owner"
	RoleBusinessAnalyst Role = "business_analyst"
	RoleArchitect       Role = "architect"
	RoleDeveloper       Role = "developer"
	RoleQA              Role = "qa"
	RoleDevOps          Role = "devops"
	RoleSecurity        Role = "security"
	RoleCompliance      Role = "compliance"
	RoleAuditor         Role = "auditor"
	RoleViewer          Role = "viewer"
)

// readOnlyBase is the floor every role that can see a project shares.
var readOnlyBase = []Permission{
	TenantRead, ProjectRead, ArtifactRead, LinkRead,
	PipelineRead, DeploymentRead, RuntimeRead, PolicyRead, PromptRead,
}

// rolePermissions is the authoritative role matrix. It mirrors the table in
// docs/architecture/05-authorization-model.md §4.2, and the matrix test asserts
// the two stay in agreement.
//
// Note what platform_admin does NOT have: any permission to read or write tenant
// artifact content. Operating the platform and reading customers' intellectual
// property are different jobs, and separating them is why break-glass exists.
var rolePermissions = map[Role][]Permission{
	RolePlatformAdmin: {
		TenantRead, TenantCreate, TenantUpdate, TenantSuspend, TenantPurge,
		PrincipalRead, RuntimeRead, PolicyRead, AuditRead,
	},

	RoleTenantAdmin: append(append([]Permission{}, readOnlyBase...),
		TenantUpdate, ProjectCreate, ProjectUpdate, ProjectArchive,
		PrincipalRead, PrincipalInvite, RoleAssign, APIKeyCreate, APIKeyRevoke,
		IdPMappingRead, IdPMappingUpdate,
		RepoConnect, ExceptionRequest, AIConfig, PromptPublish, AuditRead,
	),

	RoleProductOwner: append(append([]Permission{}, readOnlyBase...),
		ProjectCreate, ProjectUpdate,
		ArtifactCreate, ArtifactEdit, ArtifactSubmit, ArtifactReview, ArtifactApprove,
		LinkCreate, LinkAccept, LinkReject,
		PRDDiscovery, PRDUpload, PRDApprove, SpecGenerate, SpecApprove,
		ProposalApprove, GateEvaluate, ExceptionRequest, AIInvoke, FindingRead,
	),

	RoleBusinessAnalyst: append(append([]Permission{}, readOnlyBase...),
		ArtifactCreate, ArtifactEdit, ArtifactSubmit, ArtifactReview,
		LinkCreate, PRDDiscovery, PRDUpload, SpecGenerate,
		ModelGenerate, ModelEdit, ProposalSubmit, GateEvaluate,
		ExceptionRequest, AIInvoke,
	),

	RoleArchitect: append(append([]Permission{}, readOnlyBase...),
		ProjectUpdate,
		ArtifactCreate, ArtifactEdit, ArtifactSubmit, ArtifactReview, ArtifactApprove, ArtifactFreeze,
		LinkCreate, LinkAccept, LinkReject,
		SpecGenerate, SpecApprove, ModelGenerate, ModelEdit,
		CodeGenerate, CodeRead, RepoConnect, RepoIngest,
		SyncRun, ProposalSubmit, ProposalApprove,
		GateEvaluate, ExceptionRequest, ExceptionGrant, DispositionRecord, DesignAuthorityDecide,
		DeploymentApprove, FindingRead, AIInvoke, PromptPublish, AuditRead,
	),

	RoleDeveloper: append(append([]Permission{}, readOnlyBase...),
		ArtifactCreate, ArtifactEdit, ArtifactSubmit,
		LinkCreate, CodeGenerate, CodeRead, RepoConnect, RepoIngest,
		SyncRun, ProposalSubmit, GateEvaluate, ExceptionRequest,
		PipelineTrigger, FindingRead, AIInvoke, PromptPublish,
	),

	RoleQA: append(append([]Permission{}, readOnlyBase...),
		ArtifactCreate, ArtifactEdit, ArtifactSubmit, ArtifactReview,
		LinkCreate, CodeRead, ProposalSubmit, GateEvaluate,
		ExceptionRequest, ScanRun, FindingRead,
	),

	RoleDevOps: append(append([]Permission{}, readOnlyBase...),
		RepoConnect, CodeRead,
		PipelineTrigger, PipelineApprove, DeploymentApprove, DeploymentRollback,
		IncidentAck, IncidentManage, EscalationManage,
		GateEvaluate, ExceptionRequest, ScanRun, FindingRead,
	),

	RoleSecurity: append(append([]Permission{}, readOnlyBase...),
		ArtifactReview, CodeRead, LinkRead,
		GateEvaluate, ExceptionRequest, ExceptionGrant, DispositionRecord, DesignAuthorityDecide,
		ProposalApprove, DeploymentApprove,
		ScanRun, FindingRead, FindingSuppress,
		AIConfig, GuardrailConfig, PromptPublish,
		IncidentAck, IncidentManage, AuditRead,
	),

	RoleCompliance: append(append([]Permission{}, readOnlyBase...),
		ArtifactReview, GateEvaluate,
		ExceptionRequest, ExceptionGrant, DispositionRecord, DesignAuthorityDecide,
		ProposalApprove, DeploymentApprove,
		FindingRead, FindingSuppress,
		AuditRead, AuditExport,
	),

	RoleAuditor: append(append([]Permission{}, readOnlyBase...),
		PrincipalRead, CodeRead, FindingRead, AuditRead, AuditExport,
	),

	RoleViewer: append([]Permission{}, readOnlyBase...),
}

// roleSets is the precomputed bitset for each role.
var roleSets = func() map[Role]Set {
	m := make(map[Role]Set, len(rolePermissions))
	for r, perms := range rolePermissions {
		m[r] = NewSet(perms...)
	}
	return m
}()

// AllRoles returns every role, sorted.
func AllRoles() []Role {
	out := make([]Role, 0, len(rolePermissions))
	for r := range rolePermissions {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Valid reports whether r is a known role.
func (r Role) Valid() bool { _, ok := rolePermissions[r]; return ok }

// ParseRole resolves a role name.
func ParseRole(s string) (Role, error) {
	r := Role(strings.ToLower(strings.TrimSpace(s)))
	if !r.Valid() {
		return "", fmt.Errorf("unknown role %q", s)
	}
	return r, nil
}

// Permissions returns the role's permission set.
func (r Role) Permissions() Set { return roleSets[r] }

// PermissionNames returns the role's permissions as sorted names.
func (r Role) PermissionNames() []string { return roleSets[r].Names() }

// SetForRoles unions the permissions of several roles.
func SetForRoles(roles ...Role) Set {
	var s Set
	for _, r := range roles {
		s = s.Union(roleSets[r])
	}
	return s
}

// ServiceAccountSet clamps a permission set to what a non-human principal may
// hold. This is SoD-6 enforced at set construction, so a service account cannot
// acquire approval authority through any grant path.
func ServiceAccountSet(s Set) Set { return s.Without(approvalPermissions) }

// Grant is a role assignment at tenant or project scope.
type Grant struct {
	Role Role
	// ProjectID is empty for a tenant-wide grant.
	ProjectID string
}

// Resolve computes the effective permission set for a set of grants, evaluated
// against a specific project scope.
//
// A tenant-wide grant applies everywhere in the tenant. A project grant applies
// only to that project, and never widens access to a different project.
func Resolve(grants []Grant, projectID string) Set {
	var s Set
	for _, g := range grants {
		if g.ProjectID != "" && g.ProjectID != projectID {
			continue
		}
		s = s.Union(roleSets[g.Role])
	}
	return s
}
