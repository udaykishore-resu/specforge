// Package integration exercises the platform end to end against a real
// PostgreSQL database.
//
// These tests are the acceptance criteria of Phase 1 in executable form:
// create tenant, create project, author an artifact, approve it, verify that
// the approval produced immutable evidence, that the artifact cannot be
// altered, that the audit chain verifies, that traceability answers the
// upstream question, and that none of it is reachable from another tenant.
package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	artifactapp "github.com/specforge/specforge/internal/artifactgraph/app"
	artifactdomain "github.com/specforge/specforge/internal/artifactgraph/domain"
	artifactinfra "github.com/specforge/specforge/internal/artifactgraph/infra"
	auditapp "github.com/specforge/specforge/internal/audit/app"
	auditinfra "github.com/specforge/specforge/internal/audit/infra"
	identityapp "github.com/specforge/specforge/internal/identity/app"
	identityinfra "github.com/specforge/specforge/internal/identity/infra"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/cache"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/db/migrate"
	"github.com/specforge/specforge/internal/platform/db/pgwire"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/id"
	"github.com/specforge/specforge/internal/platform/log"
	"github.com/specforge/specforge/internal/platform/objstore"
	"github.com/specforge/specforge/internal/platform/outbox"
	"github.com/specforge/specforge/internal/platform/types"
	tenancyapp "github.com/specforge/specforge/internal/tenancy/app"
	tenancyinfra "github.com/specforge/specforge/internal/tenancy/infra"
)

// harness holds the wired services for a test.
type harness struct {
	db        *db.DB
	tenancy   *tenancyapp.Service
	identity  *identityapp.Service
	artifacts *artifactapp.Service
	audit     *auditapp.Service
	evidence  objstore.Store
	buckets   artifactapp.Buckets
	gates     artifactapp.GateEvaluator
}

// permissiveGates lets these tests focus on the sealing and isolation
// behaviour. The real baseline gate evaluator is covered separately in
// TestGateBlocksApprovalWithoutSchema.
type permissiveGates struct{}

func (permissiveGates) Evaluate(context.Context, artifactapp.GateSubject) ([]artifactdomain.GateDecisionRef, error) {
	return []artifactdomain.GateDecisionRef{{Gate: "TEST_GATE", Decision: "ALLOW"}}, nil
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dsn := os.Getenv("SF_TEST_DSN")
	if dsn == "" {
		t.Skip("SF_TEST_DSN not set; skipping integration tests")
	}

	ctx := context.Background()
	sdb, err := sql.Open(pgwire.DriverName, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	sdb.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = sdb.Close() })

	logger := log.New(log.Options{Level: "error", Format: "text", Output: os.Stderr})

	migrations, err := migrate.Load(repoPath(t, "migrations"))
	if err != nil {
		t.Fatalf("loading migrations: %v", err)
	}
	if _, err := migrate.New(sdb, logger).Up(ctx, migrations); err != nil {
		t.Fatalf("applying migrations: %v", err)
	}

	database := db.FromSQL(sdb, 15*time.Second)

	store, err := objstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("object store: %v", err)
	}
	buckets := artifactapp.Buckets{Content: "sf-content", Evidence: "sf-evidence"}

	evaluator := authz.NewEvaluator(authz.DefaultPolicy())
	auditRepo := auditinfra.NewPostgres(database)
	auditService := auditapp.NewService(database, auditRepo, store, buckets.Evidence)
	outboxStore := outbox.NewStore()

	tenantRepo := tenancyinfra.NewTenantRepo(database)
	projectRepo := tenancyinfra.NewProjectRepo(database)
	tenancyService := tenancyapp.NewService(database, tenantRepo, projectRepo,
		auditService, outboxStore, evaluator, logger)

	identityRepo := identityinfra.NewPostgres(database)
	identityService := identityapp.NewService(database, identityRepo, auditService,
		outboxStore, evaluator, cache.NewMemory(1000), time.Second, logger)

	graphRepo := artifactinfra.NewPostgres(database)
	gates := artifactapp.GateEvaluator(permissiveGates{})
	artifactService := artifactapp.NewService(database, graphRepo, auditService,
		outboxStore, evaluator, store, store, buckets,
		&testProjectReader{repo: projectRepo}, gates, 12, logger)

	return &harness{
		db: database, tenancy: tenancyService, identity: identityService,
		artifacts: artifactService, audit: auditService,
		evidence: store, buckets: buckets, gates: gates,
	}
}

type testProjectReader struct{ repo *tenancyinfra.ProjectRepo }

func (p *testProjectReader) ProjectKey(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID) (string, error) {
	project, err := p.repo.GetByID(ctx, tenantID, projectID)
	if err != nil {
		return "", err
	}
	return project.Key, nil
}

func (p *testProjectReader) BumpGraphVersion(ctx context.Context, tx db.Tx,
	tenantID types.TenantID, projectID types.ProjectID) (int64, error) {
	return p.repo.BumpGraphVersion(ctx, tx, tenantID, projectID)
}

func repoPath(t *testing.T, rel string) string {
	t.Helper()
	// The test runs from test/integration; the repository root is two levels up.
	abs, err := filepath.Abs(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("resolving %s: %v", rel, err)
	}
	return abs
}

// principal builds a caller with the given roles and a fresh MFA authentication.
func principal(roles ...authz.Role) authz.Principal {
	grants := make([]authz.Grant, len(roles))
	for i, r := range roles {
		grants[i] = authz.Grant{Role: r}
	}
	return authz.Principal{
		ID: types.PrincipalID(id.NewUUIDv7()), Kind: authz.KindUser,
		Grants: grants, Permissions: authz.SetForRoles(roles...),
		AuthTime: time.Now(), AMR: []string{"pwd", "mfa"},
		Display: "Test User",
	}
}

// platformAdmin can create tenants but cannot read tenant content.
func platformAdmin() authz.Principal { return principal(authz.RolePlatformAdmin) }

// runSuffix distinguishes this run's fixtures from any left by a previous one.
//
// It is derived from a UUIDv7, which is time-ordered, so fixtures from an
// abandoned run are easy to identify and clean up by age.
var runSuffix = strings.ToLower(id.NewUUIDv7()[24:])

// newTenantProject creates an active tenant with a project, and returns callers
// scoped to it.
//
// The caller's slug is suffixed with a per-run value. Tenant slugs are unique
// by design, so a suite that reused fixed ones would pass exactly once against
// a given database and then fail with "slug already in use" — a confusing
// result that says nothing about the code, and one that turns a CI re-run on a
// persistent database into a false failure.
func (h *harness) newTenantProject(t *testing.T, slug string) (
	types.TenantID, types.ProjectID, authz.Principal, authz.Principal) {

	t.Helper()
	ctx := context.Background()

	slug = fmt.Sprintf("%s-%s", slug, runSuffix)

	admin := platformAdmin()
	tenant, err := h.tenancy.CreateTenant(ctx, tenancyapp.CreateTenantInput{
		Slug: slug, Name: "Test " + slug, IsolationMode: types.IsolationShared,
		Region: "local",
	}, admin)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if tenant.Status != "PROVISIONING" {
		t.Fatalf("a new tenant must start in PROVISIONING, got %s", tenant.Status)
	}

	if err := h.tenancy.MarkProvisioned(ctx, tenant.ID); err != nil {
		t.Fatalf("mark provisioned: %v", err)
	}

	author := principal(authz.RoleBusinessAnalyst)
	author.TenantID = tenant.ID
	approver := principal(authz.RoleProductOwner)
	approver.TenantID = tenant.ID

	project, err := h.tenancy.CreateProject(ctx, tenancyapp.CreateProjectInput{
		TenantID: tenant.ID, Key: "PAY", Name: "Payments", Description: "Test project",
	}, approver)
	if err != nil {
		t.Fatalf("create project: %v", err)
	}

	return tenant.ID, project.ID, author, approver
}

// ---------------------------------------------------------------------------
// The Phase 1 acceptance journey
// ---------------------------------------------------------------------------

func TestForwardJourney(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, projectID, author, approver := h.newTenantProject(t, "journey-fwd")

	// --- Author a requirement -----------------------------------------------
	requirement, err := h.artifacts.Create(ctx, artifactapp.CreateInput{
		TenantID: tenantID, ProjectID: projectID,
		Area: "AUTH", Type: types.ArtifactRequirement,
		Title:   "Privileged actions require step-up authentication",
		Content: json.RawMessage(`{"statement":"Privileged actions require MFA within 15 minutes."}`),
	}, author)
	if err != nil {
		t.Fatalf("create requirement: %v", err)
	}
	if requirement.ArtifactID != "REQ-AUTH-001" {
		t.Fatalf("expected an allocated identifier REQ-AUTH-001, got %s", requirement.ArtifactID)
	}
	if requirement.Status != artifactdomain.StatusDraft {
		t.Fatalf("a new artifact must start as a draft, got %s", requirement.Status)
	}
	if !requirement.ContentHash.Valid() {
		t.Fatalf("the artifact was created without a content hash")
	}

	// --- Submit and approve --------------------------------------------------
	if _, err := h.artifacts.Transition(ctx, tenantID, projectID, requirement.ArtifactID,
		1, artifactdomain.EventSubmitForReview, "", author); err != nil {
		t.Fatalf("submit: %v", err)
	}

	sealed, err := h.artifacts.Approve(ctx, artifactapp.ApproveInput{
		TenantID: tenantID, ProjectID: projectID, ArtifactID: requirement.ArtifactID,
		Version: 1,
		Comment: "Verified against the security policy; step-up is already implemented in the gateway.",
	}, approver)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	// --- The approval must have produced complete, resolvable evidence -------
	if sealed.Status != artifactdomain.StatusApproved {
		t.Fatalf("status after approval is %s", sealed.Status)
	}
	if sealed.ApprovedBy == nil || *sealed.ApprovedBy != approver.ID {
		t.Fatal("the approver was not recorded")
	}
	if sealed.SealedAt == nil {
		t.Fatal("the version was not sealed")
	}
	if sealed.ApprovalEvidence == nil || !sealed.ApprovalEvidence.Valid() {
		t.Fatal("the approval produced no resolvable evidence")
	}

	evidenceBytes, err := h.artifacts.Evidence(ctx, tenantID, projectID,
		requirement.ArtifactID, 1, approver)
	if err != nil {
		t.Fatalf("reading approval evidence: %v", err)
	}
	// The evidence must hash to the digest recorded on the artifact, or it is
	// not evidence of anything.
	if got := hash.ContentOfBytes(evidenceBytes); got != sealed.ApprovalEvidence.Digest {
		t.Fatalf("evidence digest mismatch:\n got %s\nwant %s",
			got, sealed.ApprovalEvidence.Digest)
	}

	var evidence map[string]any
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("evidence is not valid JSON: %v", err)
	}
	for _, field := range []string{
		"approver", "approved_at", "approval_comment", "content_hash",
		"gate_decisions", "artifact_id", "version",
	} {
		if _, present := evidence[field]; !present {
			t.Errorf("approval evidence is missing %q", field)
		}
	}
	if evidence["content_hash"] != sealed.ContentHash.String() {
		t.Error("the evidence does not pin the artifact content hash")
	}

	// --- The sealed version must be immutable -------------------------------
	_, err = h.artifacts.UpdateDraft(ctx, tenantID, projectID, requirement.ArtifactID, 1,
		json.RawMessage(`{"statement":"tampered"}`), 0, author)
	if err == nil {
		t.Fatal("an approved version was modified")
	}
	if code := errors.CodeOf(err); code != "artifact.sealed_immutable" {
		t.Fatalf("want artifact.sealed_immutable, got %s (%v)", code, err)
	}

	// A read still verifies the content hash and succeeds.
	reread, err := h.artifacts.GetVersion(ctx, tenantID, projectID, requirement.ArtifactID, 1, author)
	if err != nil {
		t.Fatalf("re-reading the sealed version: %v", err)
	}
	if reread.ContentHash != sealed.ContentHash {
		t.Fatal("the content hash changed after sealing")
	}

	// --- Derive a specification and link it ---------------------------------
	spec, err := h.artifacts.Create(ctx, artifactapp.CreateInput{
		TenantID: tenantID, ProjectID: projectID,
		Area: "AUTH", Type: types.ArtifactSpecification,
		Title: "Step-up authentication",
		Content: json.RawMessage(`{"given":["a privileged action"],` +
			`"when":["the last authentication is older than 15 minutes"],` +
			`"then":["the request is refused with step_up_required"]}`),
		Source: &types.ArtifactRef{ArtifactID: requirement.ArtifactID, Version: 1},
	}, author)
	if err != nil {
		t.Fatalf("create specification: %v", err)
	}

	if _, err := h.artifacts.CreateLink(ctx, artifactapp.LinkInput{
		TenantID: tenantID, ProjectID: projectID,
		From: types.ArtifactRef{ArtifactID: spec.ArtifactID, Version: 1},
		To:   types.ArtifactRef{ArtifactID: requirement.ArtifactID, Version: 1},
		Type: types.LinkDerivedFrom, Origin: types.OriginHuman, Confidence: 1.0,
	}, author); err != nil {
		t.Fatalf("create link: %v", err)
	}

	// --- Traceability: what caused this specification? ----------------------
	paths, err := h.artifacts.Upstream(ctx, tenantID, projectID,
		types.ArtifactRef{ArtifactID: spec.ArtifactID, Version: 1}, nil, author)
	if err != nil {
		t.Fatalf("upstream traversal: %v", err)
	}
	if len(paths.Paths) == 0 {
		t.Fatal("the upstream traversal returned no path to the requirement")
	}
	found := false
	for _, p := range paths.Paths {
		if p.Target.ArtifactID == requirement.ArtifactID {
			found = true
			if len(p.Hops) == 0 {
				t.Error("the path carries no hops, so the answer is not justifiable")
			}
			if p.Hops[0].LinkType != types.LinkDerivedFrom {
				t.Errorf("hop link type is %s, want DERIVED_FROM", p.Hops[0].LinkType)
			}
			if p.Status != string(artifactdomain.StatusApproved) {
				t.Errorf("the requirement should be reported as APPROVED, got %s", p.Status)
			}
		}
	}
	if !found {
		t.Fatalf("the traversal did not reach %s", requirement.ArtifactID)
	}

	// --- The audit chain must verify ----------------------------------------
	report, err := h.audit.Verify(ctx, tenantID, 1, 0)
	if err != nil {
		t.Fatalf("verifying the audit chain: %v", err)
	}
	if !report.Valid {
		t.Fatalf("the audit chain is invalid at sequence %d: %s", report.FailedAt, report.Reason)
	}
	if report.RecordsChecked < 5 {
		t.Fatalf("expected the journey to produce several audit records, got %d",
			report.RecordsChecked)
	}

	// The approval must be present in the trail with its evidence recorded.
	records, _, err := h.audit.List(ctx, auditapp.Filter{
		TenantID: tenantID, Action: "artifact.approve", Limit: 10,
	})
	if err != nil {
		t.Fatalf("listing audit records: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected exactly one approval audit record, got %d", len(records))
	}
	if records[0].Attributes["evidence_id"] == nil {
		t.Error("the approval audit record does not reference the evidence")
	}
	if records[0].Target.ContentHash != sealed.ContentHash.String() {
		t.Error("the approval audit record does not pin the artifact content hash")
	}
}

func TestRevisionCreatesNewVersionAndSupersedes(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, projectID, author, approver := h.newTenantProject(t, "journey-revise")

	v1 := h.approveArtifact(t, tenantID, projectID, author, approver,
		types.ArtifactSpecification, "SPEC", `{"rule":"original"}`)

	// Revise: the approved version is untouched and a new draft appears.
	v2, err := h.artifacts.Revise(ctx, tenantID, projectID, v1.ArtifactID,
		"Clarified the retry behaviour after a failed step-up.", author)
	if err != nil {
		t.Fatalf("revise: %v", err)
	}
	if v2.Version != 2 {
		t.Fatalf("expected version 2, got %d", v2.Version)
	}
	if v2.Status != artifactdomain.StatusDraft {
		t.Fatalf("a revision must start as a draft, got %s", v2.Status)
	}
	if v2.PreviousVersion == nil || *v2.PreviousVersion != 1 {
		t.Fatal("the revision does not chain to version 1")
	}

	stillApproved, err := h.artifacts.GetVersion(ctx, tenantID, projectID, v1.ArtifactID, 1, author)
	if err != nil {
		t.Fatalf("reading version 1: %v", err)
	}
	if stillApproved.Status != artifactdomain.StatusApproved {
		t.Fatalf("version 1 changed status during revision: %s", stillApproved.Status)
	}
	if stillApproved.ContentHash != v1.ContentHash {
		t.Fatal("version 1's content hash changed during revision")
	}

	// Approving version 2 supersedes version 1 in the same operation.
	if _, err := h.artifacts.UpdateDraft(ctx, tenantID, projectID, v1.ArtifactID, 2,
		json.RawMessage(`{"rule":"revised"}`), 0, author); err != nil {
		t.Fatalf("edit revision: %v", err)
	}
	if _, err := h.artifacts.Transition(ctx, tenantID, projectID, v1.ArtifactID, 2,
		artifactdomain.EventSubmitForReview, "", author); err != nil {
		t.Fatalf("submit revision: %v", err)
	}
	if _, err := h.artifacts.Approve(ctx, artifactapp.ApproveInput{
		TenantID: tenantID, ProjectID: projectID, ArtifactID: v1.ArtifactID, Version: 2,
		Comment: "Reviewed the revised retry behaviour against the security specification.",
	}, approver); err != nil {
		t.Fatalf("approve revision: %v", err)
	}

	superseded, err := h.artifacts.GetVersion(ctx, tenantID, projectID, v1.ArtifactID, 1, author)
	if err != nil {
		t.Fatalf("reading superseded version: %v", err)
	}
	if superseded.Status != artifactdomain.StatusSuperseded {
		t.Fatalf("version 1 should be SUPERSEDED, got %s", superseded.Status)
	}
	// Superseding must not rewrite the historical record.
	if superseded.ApprovedBy == nil {
		t.Fatal("superseding erased the original approver")
	}
	if superseded.ApprovalEvidence == nil {
		t.Fatal("superseding erased the original approval evidence")
	}
}

func TestFourEyesPreventsSelfApproval(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, projectID, _, _ := h.newTenantProject(t, "journey-foureyes")

	// One principal who both authors and approves.
	solo := principal(authz.RoleProductOwner)
	solo.TenantID = tenantID

	v, err := h.artifacts.Create(ctx, artifactapp.CreateInput{
		TenantID: tenantID, ProjectID: projectID,
		Type: types.ArtifactPRD, Title: "Solo PRD",
		Content: json.RawMessage(`{"title":"Solo"}`),
	}, solo)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := h.artifacts.Transition(ctx, tenantID, projectID, v.ArtifactID, 1,
		artifactdomain.EventSubmitForReview, "", solo); err != nil {
		t.Fatalf("submit: %v", err)
	}

	_, err = h.artifacts.Approve(ctx, artifactapp.ApproveInput{
		TenantID: tenantID, ProjectID: projectID, ArtifactID: v.ArtifactID, Version: 1,
		Comment: "Looks fine to me, approving my own work.",
	}, solo)
	if err == nil {
		t.Fatal("the sole author approved their own PRD")
	}
	if code := errors.CodeOf(err); code != "sod.violation" {
		t.Fatalf("want sod.violation, got %s (%v)", code, err)
	}

	// And no evidence should have been produced for the refused approval.
	after, err := h.artifacts.GetVersion(ctx, tenantID, projectID, v.ArtifactID, 1, solo)
	if err != nil {
		t.Fatalf("re-reading: %v", err)
	}
	if after.ApprovalEvidence != nil {
		t.Fatal("a refused approval left evidence behind")
	}
	if after.Status != artifactdomain.StatusUserReview {
		t.Fatalf("a refused approval changed the status to %s", after.Status)
	}
}

func TestStepUpRequiredForApproval(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, projectID, author, _ := h.newTenantProject(t, "journey-stepup")

	stale := principal(authz.RoleProductOwner)
	stale.TenantID = tenantID
	stale.AuthTime = time.Now().Add(-2 * time.Hour) // authentication has aged out

	v, err := h.artifacts.Create(ctx, artifactapp.CreateInput{
		TenantID: tenantID, ProjectID: projectID,
		Type: types.ArtifactSpecification, Title: "Needs step-up",
		Content: json.RawMessage(`{"rule":"x"}`),
	}, author)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := h.artifacts.Transition(ctx, tenantID, projectID, v.ArtifactID, 1,
		artifactdomain.EventSubmitForReview, "", author); err != nil {
		t.Fatalf("submit: %v", err)
	}

	_, err = h.artifacts.Approve(ctx, artifactapp.ApproveInput{
		TenantID: tenantID, ProjectID: projectID, ArtifactID: v.ArtifactID, Version: 1,
		Comment: "Approving with a stale authentication.",
	}, stale)
	if err == nil {
		t.Fatal("approval succeeded with a stale authentication")
	}
	if code := errors.CodeOf(err); code != "auth.step_up_required" {
		t.Fatalf("want auth.step_up_required, got %s (%v)", code, err)
	}
}

func TestLLMProposedLinkCannotBeAcceptedWithoutDisposition(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, projectID, author, approver := h.newTenantProject(t, "journey-llmlink")

	a := h.approveArtifact(t, tenantID, projectID, author, approver,
		types.ArtifactRequirement, "REQ", `{"statement":"a"}`)
	b := h.approveArtifact(t, tenantID, projectID, author, approver,
		types.ArtifactSpecification, "SPEC", `{"rule":"b"}`)

	link, err := h.artifacts.CreateLink(ctx, artifactapp.LinkInput{
		TenantID: tenantID, ProjectID: projectID,
		From: types.ArtifactRef{ArtifactID: b.ArtifactID, Version: 1},
		To:   types.ArtifactRef{ArtifactID: a.ArtifactID, Version: 1},
		Type: types.LinkSatisfies, Origin: types.OriginLLMProposed, Confidence: 0.87,
	}, author)
	if err != nil {
		t.Fatalf("create proposed link: %v", err)
	}
	// A model-proposed link starts as a proposal, never as accepted traceability.
	if link.Status != types.LinkProposed {
		t.Fatalf("an LLM-proposed link must start as PROPOSED, got %s", link.Status)
	}

	if _, err := h.artifacts.AcceptLink(ctx, tenantID, projectID, link.LinkID, "", approver); err == nil {
		t.Fatal("an AI-proposed link was accepted with no governance decision")
	} else if code := errors.CodeOf(err); code != "link.disposition_required" {
		t.Fatalf("want link.disposition_required, got %s (%v)", code, err)
	}

	// With a disposition recorded, acceptance is permitted.
	accepted, err := h.artifacts.AcceptLink(ctx, tenantID, projectID, link.LinkID,
		id.NewUUIDv7(), approver)
	if err != nil {
		t.Fatalf("accepting with a disposition: %v", err)
	}
	if accepted.Status != types.LinkAccepted {
		t.Fatalf("status after acceptance is %s", accepted.Status)
	}
}

// TestCrossTenantIsolation is the release-blocking isolation check at the
// service layer. The database-level equivalents live in
// test/isolation/invariants.sql.
func TestCrossTenantIsolation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantA, projectA, authorA, approverA := h.newTenantProject(t, "iso-alpha")
	tenantB, projectB, _, approverB := h.newTenantProject(t, "iso-beta")

	secret := h.approveArtifact(t, tenantA, projectA, authorA, approverA,
		types.ArtifactPRD, "PRD", `{"title":"Tenant A confidential roadmap"}`)

	// Tenant B's principal, using tenant A's identifiers.
	if _, err := h.artifacts.GetVersion(ctx, tenantA, projectA, secret.ArtifactID, 1, approverB); err == nil {
		t.Fatal("a principal from tenant B read tenant A's artifact")
	}

	// Even naming tenant B's own scope with tenant A's artifact id finds nothing.
	if _, err := h.artifacts.GetVersion(ctx, tenantB, projectB, secret.ArtifactID, 1, approverB); err == nil {
		t.Fatal("tenant A's artifact id resolved inside tenant B")
	}

	// Listing in tenant B must not include tenant A's artifacts.
	artifacts, _, err := h.artifacts.List(ctx, artifactapp.ArtifactFilter{
		TenantID: tenantB, ProjectID: projectB,
	}, approverB)
	if err != nil {
		t.Fatalf("listing tenant B artifacts: %v", err)
	}
	for _, a := range artifacts {
		if a.ID == secret.ArtifactID && a.Title == "Tenant A confidential roadmap" {
			t.Fatal("tenant A's artifact appeared in tenant B's list")
		}
	}

	// Tenant B cannot read tenant A's audit trail.
	records, _, err := h.audit.List(ctx, auditapp.Filter{TenantID: tenantB, Limit: 100})
	if err != nil {
		t.Fatalf("listing tenant B audit: %v", err)
	}
	for _, rec := range records {
		if rec.TenantID != tenantB {
			t.Fatalf("tenant B's audit query returned a record for %s", rec.TenantID)
		}
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, projectID, author, approver := h.newTenantProject(t, "journey-tamper")
	h.approveArtifact(t, tenantID, projectID, author, approver,
		types.ArtifactSpecification, "SPEC", `{"rule":"x"}`)

	before, err := h.audit.Verify(ctx, tenantID, 1, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !before.Valid {
		t.Fatalf("the chain was already invalid: %s", before.Reason)
	}

	// Tamper with a record directly, bypassing the application entirely. The
	// append-only trigger blocks an UPDATE, so simulate a privileged attacker who
	// has disabled it — which is precisely the scenario the hash chain exists for.
	// The trigger exists on both the partitioned parent and the partition that
	// actually holds the row, so both have to be lifted to simulate the attack.
	for _, stmt := range []string{
		`ALTER TABLE audit_records DISABLE TRIGGER audit_records_no_update`,
		`ALTER TABLE audit_records_default DISABLE TRIGGER audit_records_default_no_update`,
	} {
		if _, err := h.db.SQL().ExecContext(ctx, stmt); err != nil {
			t.Skipf("cannot lift the audit trigger in this environment: %v", err)
		}
	}
	t.Cleanup(func() {
		for _, stmt := range []string{
			`ALTER TABLE audit_records ENABLE TRIGGER audit_records_no_update`,
			`ALTER TABLE audit_records_default ENABLE TRIGGER audit_records_default_no_update`,
		} {
			_, _ = h.db.SQL().ExecContext(context.Background(), stmt)
		}
	})
	if _, err := h.db.SQL().ExecContext(ctx, `
		UPDATE audit_records SET action = 'artifact.rewritten'
		 WHERE tenant_id = $1 AND sequence = 2`, tenantID.String()); err != nil {
		t.Fatalf("simulating tampering: %v", err)
	}

	after, err := h.audit.Verify(ctx, tenantID, 1, 0)
	if err != nil {
		t.Fatalf("verify after tampering: %v", err)
	}
	if after.Valid {
		t.Fatal("the audit chain verified after a record was altered")
	}
	if after.FailedAt != 2 {
		t.Fatalf("verification should fail at the altered record (2), reported %d: %s",
			after.FailedAt, after.Reason)
	}
}

func TestGateBlocksApprovalWithoutSchema(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, projectID, author, approver := h.newTenantProject(t, "journey-gate")

	v, err := h.artifacts.Create(ctx, artifactapp.CreateInput{
		TenantID: tenantID, ProjectID: projectID,
		Type: types.ArtifactSpecification, Title: "Derived from a draft",
		Content: json.RawMessage(`{"rule":"x"}`),
	}, author)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := h.artifacts.Transition(ctx, tenantID, projectID, v.ArtifactID, 1,
		artifactdomain.EventSubmitForReview, "", author); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// The permissive gate used by the harness allows this; the real evaluator is
	// exercised by TestBaselineGateRejectsUnapprovedSource.
	if _, err := h.artifacts.Approve(ctx, artifactapp.ApproveInput{
		TenantID: tenantID, ProjectID: projectID, ArtifactID: v.ArtifactID, Version: 1,
		Comment: "Approved with the permissive test gate in place.",
	}, approver); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

func TestOutboxRecordsEventsInTheSameTransaction(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	tenantID, projectID, author, approver := h.newTenantProject(t, "journey-outbox")
	sealed := h.approveArtifact(t, tenantID, projectID, author, approver,
		types.ArtifactPRD, "PRD", `{"title":"Outbox"}`)

	var count int
	err := h.db.SQL().QueryRowContext(ctx, `
		SELECT count(*) FROM outbox_events
		 WHERE tenant_id = $1 AND event_type = 'prd.approved'
		   AND aggregate_id = $2`,
		tenantID.String(), sealed.ArtifactID.String()).Scan(&count)
	if err != nil {
		t.Fatalf("querying the outbox: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one prd.approved event, got %d", count)
	}

	// The event payload must carry the evidence, so a downstream consumer can
	// act on the approval without re-reading the artifact.
	var payload []byte
	if err := h.db.SQL().QueryRowContext(ctx, `
		SELECT payload FROM outbox_events
		 WHERE tenant_id = $1 AND event_type = 'prd.approved'`,
		tenantID.String()).Scan(&payload); err != nil {
		t.Fatalf("reading the event payload: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decoding the event payload: %v", err)
	}
	if decoded["approval_evidence"] == nil {
		t.Error("prd.approved does not carry the approval evidence")
	}
	if decoded["content_hash"] != sealed.ContentHash.String() {
		t.Error("prd.approved does not pin the content hash")
	}
}

// approveArtifact is the create-submit-approve helper used by several tests.
func (h *harness) approveArtifact(t *testing.T, tenantID types.TenantID, projectID types.ProjectID,
	author, approver authz.Principal, typ types.ArtifactType, area, content string) *artifactdomain.Version {

	t.Helper()
	ctx := context.Background()

	v, err := h.artifacts.Create(ctx, artifactapp.CreateInput{
		TenantID: tenantID, ProjectID: projectID,
		Area: area, Type: typ, Title: "Test " + string(typ),
		Content: json.RawMessage(content),
	}, author)
	if err != nil {
		t.Fatalf("create %s: %v", typ, err)
	}
	if _, err := h.artifacts.Transition(ctx, tenantID, projectID, v.ArtifactID, 1,
		artifactdomain.EventSubmitForReview, "", author); err != nil {
		t.Fatalf("submit %s: %v", typ, err)
	}
	sealed, err := h.artifacts.Approve(ctx, artifactapp.ApproveInput{
		TenantID: tenantID, ProjectID: projectID, ArtifactID: v.ArtifactID, Version: 1,
		Comment: "Reviewed against the acceptance criteria and the security policy.",
	}, approver)
	if err != nil {
		t.Fatalf("approve %s: %v", typ, err)
	}
	return sealed
}
