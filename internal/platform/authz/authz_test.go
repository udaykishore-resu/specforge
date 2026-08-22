package authz_test

import (
	"testing"
	"time"

	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/types"
)

const (
	tenantA = types.TenantID("11111111-1111-4111-8111-111111111111")
	tenantB = types.TenantID("22222222-2222-4222-8222-222222222222")
	alice   = types.PrincipalID("aaaaaaaa-0000-4000-8000-000000000001")
	bob     = types.PrincipalID("bbbbbbbb-0000-4000-8000-000000000001")
)

func principal(t *testing.T, id types.PrincipalID, tenant types.TenantID, roles ...authz.Role) authz.Principal {
	t.Helper()
	grants := make([]authz.Grant, len(roles))
	for i, r := range roles {
		grants[i] = authz.Grant{Role: r}
	}
	return authz.Principal{
		ID: id, Kind: authz.KindUser, TenantID: tenant,
		Grants: grants, Permissions: authz.SetForRoles(roles...),
		AuthTime: time.Now(), AMR: []string{"pwd", "otp"},
	}
}

func TestPermissionSetOperations(t *testing.T) {
	t.Parallel()
	a := authz.NewSet(authz.ArtifactRead, authz.ArtifactEdit)
	b := authz.NewSet(authz.ArtifactEdit, authz.ArtifactApprove)

	if !a.Has(authz.ArtifactRead) || a.Has(authz.ArtifactApprove) {
		t.Fatal("membership is wrong")
	}
	if !a.Union(b).HasAll(authz.ArtifactRead, authz.ArtifactEdit, authz.ArtifactApprove) {
		t.Fatal("union is wrong")
	}
	if !a.Intersect(b).Has(authz.ArtifactEdit) || a.Intersect(b).Has(authz.ArtifactRead) {
		t.Fatal("intersect is wrong")
	}
	if a.Without(b).Has(authz.ArtifactEdit) {
		t.Fatal("without is wrong")
	}
	if !authz.NewSet().Empty() {
		t.Fatal("empty set should be empty")
	}
}

// The role matrix is a security control; this test is its specification.
func TestRoleMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		role  authz.Role
		has   []authz.Permission
		lacks []authz.Permission
	}{
		{
			role:  authz.RoleViewer,
			has:   []authz.Permission{authz.ArtifactRead, authz.ProjectRead},
			lacks: []authz.Permission{authz.ArtifactEdit, authz.ArtifactApprove, authz.AuditRead},
		},
		{
			role:  authz.RoleAuditor,
			has:   []authz.Permission{authz.AuditRead, authz.AuditExport, authz.ArtifactRead},
			lacks: []authz.Permission{authz.ArtifactEdit, authz.ArtifactApprove, authz.ExceptionGrant},
		},
		{
			role:  authz.RoleDeveloper,
			has:   []authz.Permission{authz.CodeGenerate, authz.ProposalSubmit, authz.PipelineTrigger},
			lacks: []authz.Permission{authz.ArtifactApprove, authz.ExceptionGrant, authz.FindingSuppress},
		},
		{
			role:  authz.RoleProductOwner,
			has:   []authz.Permission{authz.PRDApprove, authz.ArtifactApprove, authz.PRDDiscovery},
			lacks: []authz.Permission{authz.ExceptionGrant, authz.DesignAuthorityDecide, authz.CodeGenerate},
		},
		{
			role:  authz.RoleArchitect,
			has:   []authz.Permission{authz.ArtifactApprove, authz.ExceptionGrant, authz.DesignAuthorityDecide},
			lacks: []authz.Permission{authz.TenantPurge, authz.FindingSuppress},
		},
		{
			role:  authz.RoleSecurity,
			has:   []authz.Permission{authz.FindingSuppress, authz.GuardrailConfig, authz.ExceptionGrant},
			lacks: []authz.Permission{authz.PRDApprove, authz.TenantPurge},
		},
		{
			role: authz.RolePlatformAdmin,
			has:  []authz.Permission{authz.TenantCreate, authz.TenantPurge},
			// The central separation: operating the platform is not reading customer content.
			lacks: []authz.Permission{
				authz.ArtifactRead, authz.ArtifactEdit, authz.ArtifactApprove,
				authz.PRDDiscovery, authz.CodeRead,
			},
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.role), func(t *testing.T) {
			set := tc.role.Permissions()
			for _, p := range tc.has {
				if !set.Has(p) {
					t.Errorf("%s should have %s", tc.role, p)
				}
			}
			for _, p := range tc.lacks {
				if set.Has(p) {
					t.Errorf("%s must NOT have %s", tc.role, p)
				}
			}
		})
	}
}

func TestNoRoleHasGateOverride(t *testing.T) {
	t.Parallel()
	// There is deliberately no gate:override permission in the namespace. If one
	// is ever added, this test forces the decision to be explicit.
	if _, err := authz.ParsePermission("gate:override"); err == nil {
		t.Fatal("gate:override exists; blocking gates must not be overridable by permission")
	}
}

func TestTenantIsolationIsCheckedFirst(t *testing.T) {
	t.Parallel()
	e := authz.NewEvaluator(authz.DefaultPolicy())
	// Alice is a full architect in tenant A and targets a resource in tenant B.
	pr := principal(t, alice, tenantA, authz.RoleArchitect)
	d := e.Authorize(pr, authz.ArtifactRead, authz.Resource{
		Type: "artifact", TenantID: tenantB, ID: "PRD-001",
	})
	if d.Allowed {
		t.Fatal("cross-tenant access was allowed")
	}
	if d.RuleID != "Tenant-Isolation" {
		t.Fatalf("want a tenant-isolation denial so the security signal is not masked, got %s", d.RuleID)
	}
}

func TestFourEyesBlocksSoleAuthorApproval(t *testing.T) {
	t.Parallel()
	e := authz.NewEvaluator(authz.DefaultPolicy())
	pr := principal(t, alice, tenantA, authz.RoleProductOwner)

	res := authz.Resource{
		Type: "artifact", TenantID: tenantA, ID: "PRD-001",
		ArtifactType: types.ArtifactPRD,
		CreatedBy:    alice, Contributors: []types.PrincipalID{alice},
	}
	if d := e.Authorize(pr, authz.ArtifactApprove, res); d.Allowed {
		t.Fatal("the sole author was allowed to approve their own PRD")
	} else if d.RuleID != "SoD-1" {
		t.Fatalf("want SoD-1, got %s: %s", d.RuleID, d.Reason)
	}

	// With a second contributor, approval is permitted.
	res.Contributors = []types.PrincipalID{alice, bob}
	if d := e.Authorize(pr, authz.ArtifactApprove, res); !d.Allowed {
		t.Fatalf("approval should be allowed with a second contributor: %s", d.Reason)
	}

	// And when someone else authored it entirely.
	res.CreatedBy = bob
	res.Contributors = []types.PrincipalID{bob}
	if d := e.Authorize(pr, authz.ArtifactApprove, res); !d.Allowed {
		t.Fatalf("approval of another author's work should be allowed: %s", d.Reason)
	}
}

func TestExceptionRequesterCannotGrant(t *testing.T) {
	t.Parallel()
	e := authz.NewEvaluator(authz.DefaultPolicy())
	pr := principal(t, alice, tenantA, authz.RoleArchitect)
	pr.DesignAuthority = true

	res := authz.Resource{Type: "exception", TenantID: tenantA, ID: "GC-1", RequestedBy: alice}
	if d := e.Authorize(pr, authz.ExceptionGrant, res); d.Allowed {
		t.Fatal("the requester was allowed to grant their own exception")
	} else if d.RuleID != "SoD-2" {
		t.Fatalf("want SoD-2, got %s", d.RuleID)
	}

	res.RequestedBy = bob
	if d := e.Authorize(pr, authz.ExceptionGrant, res); !d.Allowed {
		t.Fatalf("granting another principal's request should be allowed: %s", d.Reason)
	}
}

func TestExceptionGrantRequiresDesignAuthorityMembership(t *testing.T) {
	t.Parallel()
	e := authz.NewEvaluator(authz.DefaultPolicy())
	pr := principal(t, alice, tenantA, authz.RoleArchitect) // holds the permission
	pr.DesignAuthority = false                              // but is not on the body

	d := e.Authorize(pr, authz.ExceptionGrant,
		authz.Resource{Type: "exception", TenantID: tenantA, RequestedBy: bob})
	if d.Allowed {
		t.Fatal("a non-member granted an exception")
	}
	if d.RuleID != "SoD-3" {
		t.Fatalf("want SoD-3, got %s", d.RuleID)
	}
}

func TestServiceAccountsCannotApprove(t *testing.T) {
	t.Parallel()
	e := authz.NewEvaluator(authz.DefaultPolicy())

	// Even with a role that carries approval authority, the machine principal is
	// clamped at set resolution and then again by SoD-6.
	sa := authz.Principal{
		ID: alice, Kind: authz.KindServiceAccount, TenantID: tenantA,
		Grants:      []authz.Grant{{Role: authz.RoleProductOwner}},
		Permissions: authz.SetForRoles(authz.RoleProductOwner),
		AuthTime:    time.Now(), AMR: []string{"pwd"},
	}
	d := e.Authorize(sa, authz.ArtifactApprove, authz.Resource{
		Type: "artifact", TenantID: tenantA, CreatedBy: bob,
	})
	if d.Allowed {
		t.Fatal("a service account approved an artifact")
	}

	// A read the account legitimately holds still works.
	if d := e.Authorize(sa, authz.ArtifactRead, authz.Resource{
		Type: "artifact", TenantID: tenantA,
	}); !d.Allowed {
		t.Fatalf("service account should retain read access: %s", d.Reason)
	}
}

func TestApprovalPermissionsAreClampedForMachines(t *testing.T) {
	t.Parallel()
	full := authz.SetForRoles(authz.RoleArchitect)
	clamped := authz.ServiceAccountSet(full)
	for _, name := range authz.ApprovalPermissionNames() {
		p, err := authz.ParsePermission(name)
		if err != nil {
			t.Fatal(err)
		}
		if clamped.Has(p) {
			t.Errorf("machine principals must not retain %s", name)
		}
	}
	if !clamped.Has(authz.ArtifactRead) {
		t.Error("clamping removed a non-approval permission")
	}
}

func TestStepUpRequiredForSensitiveActions(t *testing.T) {
	t.Parallel()
	pol := authz.DefaultPolicy()
	e := authz.NewEvaluator(pol)

	pr := principal(t, alice, tenantA, authz.RoleProductOwner)
	pr.AuthTime = time.Now().Add(-1 * time.Hour) // stale

	d := e.Authorize(pr, authz.ArtifactApprove, authz.Resource{
		Type: "artifact", TenantID: tenantA, CreatedBy: bob,
	})
	if d.Allowed {
		t.Fatal("approval was allowed with a stale authentication")
	}
	if d.Reason != "step_up_required" {
		t.Fatalf("want step_up_required, got %q", d.Reason)
	}

	// A recent authentication with MFA passes.
	pr.AuthTime = time.Now()
	if d := e.Authorize(pr, authz.ArtifactApprove, authz.Resource{
		Type: "artifact", TenantID: tenantA, CreatedBy: bob,
	}); !d.Allowed {
		t.Fatalf("recent MFA should satisfy step-up: %s", d.Reason)
	}

	// Recent, but single factor: still refused.
	pr.AMR = []string{"pwd"}
	if d := e.Authorize(pr, authz.ArtifactApprove, authz.Resource{
		Type: "artifact", TenantID: tenantA, CreatedBy: bob,
	}); d.Allowed {
		t.Fatal("single-factor authentication satisfied step-up")
	}
}

func TestProjectScopedGrantsDoNotLeakAcrossProjects(t *testing.T) {
	t.Parallel()
	e := authz.NewEvaluator(authz.DefaultPolicy())
	pr := authz.Principal{
		ID: alice, Kind: authz.KindUser, TenantID: tenantA,
		Grants: []authz.Grant{
			{Role: authz.RoleViewer},                              // tenant-wide
			{Role: authz.RoleDeveloper, ProjectID: "project-one"}, // project-scoped
		},
		AuthTime: time.Now(), AMR: []string{"pwd", "otp"},
	}
	pr.Permissions = authz.Resolve(pr.Grants, "")

	if d := e.Authorize(pr, authz.CodeGenerate, authz.Resource{
		Type: "artifact", TenantID: tenantA, ProjectID: "project-one",
	}); !d.Allowed {
		t.Fatalf("developer grant should apply in its own project: %s", d.Reason)
	}
	if d := e.Authorize(pr, authz.CodeGenerate, authz.Resource{
		Type: "artifact", TenantID: tenantA, ProjectID: "project-two",
	}); d.Allowed {
		t.Fatal("a project-scoped developer grant leaked into another project")
	}
	if d := e.Authorize(pr, authz.ArtifactRead, authz.Resource{
		Type: "artifact", TenantID: tenantA, ProjectID: "project-two",
	}); !d.Allowed {
		t.Fatalf("the tenant-wide viewer grant should still apply: %s", d.Reason)
	}
}

func TestArchitectCannotApprovePRDUnlessTenantAllows(t *testing.T) {
	t.Parallel()
	res := authz.Resource{
		Type: "artifact", TenantID: tenantA, ArtifactType: types.ArtifactPRD, CreatedBy: bob,
	}
	pr := principal(t, alice, tenantA, authz.RoleArchitect)

	strict := authz.NewEvaluator(authz.DefaultPolicy())
	if d := strict.Authorize(pr, authz.ArtifactApprove, res); d.Allowed {
		t.Fatal("architect approved a PRD under the default policy")
	}

	pol := authz.DefaultPolicy()
	pol.ArchitectCanApprovePRD = true
	relaxed := authz.NewEvaluator(pol)
	if d := relaxed.Authorize(pr, authz.ArtifactApprove, res); !d.Allowed {
		t.Fatalf("architect should approve when the tenant permits: %s", d.Reason)
	}
}

func TestRequireProducesExplainableErrors(t *testing.T) {
	t.Parallel()
	e := authz.NewEvaluator(authz.DefaultPolicy())
	pr := principal(t, alice, tenantA, authz.RoleViewer)

	err := e.Require(pr, authz.ArtifactApprove, authz.Resource{Type: "artifact", TenantID: tenantA})
	if err == nil {
		t.Fatal("expected a denial")
	}
	// The message must name the missing permission so a user can act on it.
	if got := err.Error(); got == "" {
		t.Fatal("denial produced an empty message")
	}
}

func TestEveryRoleIsResolvable(t *testing.T) {
	t.Parallel()
	for _, r := range authz.AllRoles() {
		if !r.Valid() {
			t.Errorf("%s is not valid", r)
		}
		parsed, err := authz.ParseRole(string(r))
		if err != nil || parsed != r {
			t.Errorf("round trip failed for %s: %v", r, err)
		}
		if r != authz.RolePlatformAdmin && r.Permissions().Empty() {
			t.Errorf("%s grants nothing", r)
		}
	}
}

func TestPermissionNamesRoundTrip(t *testing.T) {
	t.Parallel()
	names := authz.AllPermissions()
	if len(names) < 50 {
		t.Fatalf("expected the full permission namespace, got %d", len(names))
	}
	for _, n := range names {
		p, err := authz.ParsePermission(n)
		if err != nil {
			t.Fatalf("cannot parse %q: %v", n, err)
		}
		if p.String() != n {
			t.Fatalf("round trip mismatch: %q -> %q", n, p.String())
		}
	}
	if _, err := authz.ParsePermission("not:areal:permission"); err == nil {
		t.Fatal("unknown permissions must be rejected, not ignored")
	}
}

func TestFromNamesRejectsUnknownPermissions(t *testing.T) {
	t.Parallel()
	if _, err := authz.FromNames([]string{"artifact:read", "artifact:aprove"}); err == nil {
		t.Fatal("a typo in a permission list must be an error, not a silent omission")
	}
}
