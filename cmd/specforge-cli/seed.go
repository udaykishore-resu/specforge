package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/id"
	"github.com/specforge/specforge/internal/platform/log"
	"github.com/specforge/specforge/internal/platform/objstore"
	"github.com/specforge/specforge/internal/platform/outbox"
	"github.com/specforge/specforge/internal/platform/types"
	tenancyapp "github.com/specforge/specforge/internal/tenancy/app"
	tenancyinfra "github.com/specforge/specforge/internal/tenancy/infra"
)

// seedGates allows the demo data to be created without a policy set loaded.
type seedGates struct{}

func (seedGates) Evaluate(context.Context, artifactapp.GateSubject) ([]artifactdomain.GateDecisionRef, error) {
	return []artifactdomain.GateDecisionRef{{Gate: "SEED_GATE", Decision: "ALLOW"}}, nil
}

type seedProjectReader struct{ repo *tenancyinfra.ProjectRepo }

func (p *seedProjectReader) ProjectKey(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID) (string, error) {
	project, err := p.repo.GetByID(ctx, tenantID, projectID)
	if err != nil {
		return "", err
	}
	return project.Key, nil
}

func (p *seedProjectReader) BumpGraphVersion(ctx context.Context, tx db.Tx,
	tenantID types.TenantID, projectID types.ProjectID) (int64, error) {
	return p.repo.BumpGraphVersion(ctx, tx, tenantID, projectID)
}

// seed creates a demo tenant with a traceable artifact graph.
//
// The seeded data walks the whole forward journey so the platform is
// demonstrable immediately after `make dev`: an approved requirement, a
// specification derived from it, an accepted trace link between them, and a
// verifiable audit chain covering all of it.
func seed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	slug := fs.String("tenant-slug", "acme", "tenant slug")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	database, cfg, _, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = database.Close() }()

	logger := log.New(log.Options{Level: "info", Format: "text", ServiceName: "seed"})

	store, err := objstore.Open(cfg.ObjStore.Provider, cfg.ObjStore.Root, database.SQL())
	if err != nil {
		return err
	}
	buckets := artifactapp.Buckets{
		Content: cfg.ObjStore.ContentBucket, Evidence: cfg.ObjStore.EvidenceBucket,
	}

	evaluator := authz.NewEvaluator(authz.DefaultPolicy())
	auditService := auditapp.NewService(database, auditinfra.NewPostgres(database),
		store, buckets.Evidence)
	outboxStore := outbox.NewStore()

	identityRepo := identityinfra.NewPostgres(database)
	identityService := identityapp.NewService(database, identityRepo, auditService,
		outboxStore, evaluator, cache.NewMemory(256), time.Minute, logger)

	tenantRepo := tenancyinfra.NewTenantRepo(database)
	projectRepo := tenancyinfra.NewProjectRepo(database)
	tenancyService := tenancyapp.NewService(database, tenantRepo, projectRepo,
		auditService, outboxStore, evaluator, logger)

	graphRepo := artifactinfra.NewPostgres(database)
	artifactService := artifactapp.NewService(database, graphRepo, auditService,
		outboxStore, evaluator, store, store, buckets,
		&seedProjectReader{repo: projectRepo}, seedGates{}, 12, logger)

	// Seeded principals mirror the roles the development identity provider issues.
	admin := seedPrincipal(authz.RolePlatformAdmin)
	analyst := seedPrincipal(authz.RoleBusinessAnalyst)
	owner := seedPrincipal(authz.RoleProductOwner)

	// The seeder is idempotent by design. `make dev` is the documented way in,
	// and people run it repeatedly — after a crash, after pulling, to get back
	// to a known state. A seeder that fails the second time turns the entry
	// point into something you have to remember not to run twice.
	tenant, err := tenantRepo.GetBySlug(ctx, *slug)
	if err != nil && errors.KindOf(err) != errors.KindNotFound {
		return fmt.Errorf("looking for an existing demo tenant: %w", err)
	}

	if tenant == nil {
		tenant, err = tenancyService.CreateTenant(ctx, tenancyapp.CreateTenantInput{
			Slug: *slug, Name: "Acme Financial Services",
			IsolationMode: types.IsolationShared, Region: "local",
		}, admin)
		if err != nil {
			return fmt.Errorf("creating the demo tenant: %w", err)
		}
		if err := tenancyService.MarkProvisioned(ctx, tenant.ID); err != nil {
			return fmt.Errorf("provisioning the demo tenant: %w", err)
		}
	} else {
		logger.Info("reusing the existing demo tenant", "slug", tenant.Slug, "tenant_id", tenant.ID)
		if tenant.Status == "PROVISIONING" {
			if err := tenancyService.MarkProvisioned(ctx, tenant.ID); err != nil {
				return fmt.Errorf("provisioning the demo tenant: %w", err)
			}
		}
	}

	analyst.TenantID = tenant.ID
	owner.TenantID = tenant.ID

	// Map identity-provider groups to roles.
	//
	// Without this, a user who signs in successfully is provisioned with no
	// grants at all and every subsequent call is refused. That is the correct
	// default — an unmapped group must not confer access — but it makes a
	// freshly seeded environment look broken, so the seed states the mapping
	// explicitly rather than leaving it to be discovered through 403s.
	mappingCtx := db.WithTenant(ctx, db.TenantContext{TenantID: tenant.ID, PrincipalID: admin.ID})
	if err := database.Tx(mappingCtx, func(ctx context.Context, tx db.Tx) error {
		return identityService.SeedIdPMappings(ctx, tx, tenant.ID, admin.ID)
	}); err != nil {
		return fmt.Errorf("seeding the identity provider role mappings: %w", err)
	}

	projectCtx := db.WithTenant(ctx, db.TenantContext{TenantID: tenant.ID, PrincipalID: owner.ID})
	project, err := projectRepo.GetByKey(projectCtx, tenant.ID, "PAY")
	if err != nil && errors.KindOf(err) != errors.KindNotFound {
		return fmt.Errorf("looking for the existing demo project: %w", err)
	}
	if project == nil {
		project, err = tenancyService.CreateProject(ctx, tenancyapp.CreateProjectInput{
			TenantID: tenant.ID, Key: "PAY", Name: "Payments Platform",
			Description: "Card and account-to-account payments, with governed traceability.",
		}, owner)
		if err != nil {
			return fmt.Errorf("creating the demo project: %w", err)
		}
	} else {
		logger.Info("reusing the existing demo project", "key", project.Key, "project_id", project.ID)
	}

	requirement, err := approveSeed(ctx, artifactService, graphRepo, tenant.ID, project.ID,
		analyst, owner, artifactapp.CreateInput{
			TenantID: tenant.ID, ProjectID: project.ID,
			ArtifactID: "REQ-PAY-001",
			Area:       "PAY", Type: types.ArtifactRequirement,
			Title: "High-value payments require step-up authentication",
			Content: json.RawMessage(`{
			  "statement":"A payment above the tenant's high-value threshold must require a second authentication factor within the last 15 minutes.",
			  "rationale":"Reduces account-takeover loss on the highest-value transactions.",
			  "source":"Fraud review, Q2"
			}`),
		}, "Confirmed with the fraud team; the threshold is configurable per tenant.")
	if err != nil {
		return err
	}

	spec, err := approveSeed(ctx, artifactService, graphRepo, tenant.ID, project.ID,
		analyst, owner, artifactapp.CreateInput{
			TenantID: tenant.ID, ProjectID: project.ID,
			ArtifactID: "SPEC-PAY-001",
			Area:       "PAY", Type: types.ArtifactSpecification,
			Title:  "Step-up authentication for high-value payments",
			Source: &types.ArtifactRef{ArtifactID: requirement.ArtifactID, Version: 1},
			Content: json.RawMessage(`{
			  "type":"FUNCTIONAL",
			  "given":["an authenticated payer","a payment above the high-value threshold"],
			  "when":["the payer submits the payment"],
			  "then":["the payment is held","a step-up challenge is issued","the payment proceeds only after the challenge succeeds"],
			  "acceptance_criteria":[
			    {"id":"AC-1","text":"A payment above the threshold with an authentication older than 15 minutes is held."},
			    {"id":"AC-2","text":"A successful challenge releases the payment within 2 seconds."},
			    {"id":"AC-3","text":"A failed challenge cancels the payment and records the reason."}
			  ],
			  "security_rules":["The challenge result is bound to the payment identifier."],
			  "observability":["Emit sf_payment_stepup_total with the outcome as a label."],
			  "failure_conditions":["The authentication service is unavailable: the payment is held, never auto-released."]
			}`),
		}, "Acceptance criteria reviewed with fraud and payments engineering.")
	if err != nil {
		return err
	}

	// A duplicate link is a conflict, not a failure of the seed: the graph
	// already says what this call was going to say.
	if _, err := artifactService.CreateLink(ctx, artifactapp.LinkInput{
		TenantID: tenant.ID, ProjectID: project.ID,
		From: types.ArtifactRef{ArtifactID: spec.ArtifactID, Version: 1},
		To:   types.ArtifactRef{ArtifactID: requirement.ArtifactID, Version: 1},
		Type: types.LinkDerivedFrom, Origin: types.OriginHuman, Confidence: 1.0,
		Rationale: "The specification was written directly from the approved requirement.",
	}, analyst); err != nil && errors.KindOf(err) != errors.KindConflict {
		return fmt.Errorf("linking the specification to the requirement: %w", err)
	}

	report, err := auditService.Verify(ctx, tenant.ID, 1, 0)
	if err != nil {
		return fmt.Errorf("verifying the seeded audit chain: %w", err)
	}

	fmt.Printf(`
Demo data created.

  Tenant      %s  (%s)
  Project     %s  (%s)
  Requirement %s  APPROVED  %s
  Specification %s  APPROVED  %s
  Trace link  %s --DERIVED_FROM--> %s

  Audit chain: %d records, valid=%t

Export SF_DEV_TENANT_ID=%s and restart the API so the development identity
provider issues tokens scoped to this tenant.
`,
		tenant.Slug, tenant.ID,
		project.Key, project.ID,
		requirement.ArtifactID, requirement.ContentHash.Short(),
		spec.ArtifactID, spec.ContentHash.Short(),
		spec.ArtifactID, requirement.ArtifactID,
		report.RecordsChecked, report.Valid,
		tenant.ID)

	return nil
}

// approveSeed creates an artifact and walks it to APPROVED, or returns the
// version that is already approved.
//
// The "already there" branch is what makes a second `make seed` a no-op instead
// of an error. It deliberately returns the existing version rather than
// creating a revision: re-running the seeder should leave the demo where it
// was, not accumulate versions on every invocation.
func approveSeed(ctx context.Context, svc *artifactapp.Service, repo *artifactinfra.Postgres,
	tenantID types.TenantID, projectID types.ProjectID,
	author, approver authz.Principal, in artifactapp.CreateInput,
	comment string) (*artifactdomain.Version, error) {

	if in.ArtifactID != "" {
		scoped := db.WithTenant(ctx, db.TenantContext{
			TenantID: tenantID, ProjectID: &projectID, PrincipalID: author.ID,
		})
		existing, err := repo.ApprovedVersion(scoped, tenantID, projectID, in.ArtifactID)
		if err != nil && errors.KindOf(err) != errors.KindNotFound {
			return nil, fmt.Errorf("checking for an existing %s: %w", in.ArtifactID, err)
		}
		if existing != nil {
			return existing, nil
		}
	}

	v, err := svc.Create(ctx, in, author)
	if err != nil {
		return nil, fmt.Errorf("creating %s: %w", in.Type, err)
	}
	if _, err := svc.Transition(ctx, tenantID, projectID, v.ArtifactID, 1,
		artifactdomain.EventSubmitForReview, "", author); err != nil {
		return nil, fmt.Errorf("submitting %s: %w", v.ArtifactID, err)
	}
	sealed, err := svc.Approve(ctx, artifactapp.ApproveInput{
		TenantID: tenantID, ProjectID: projectID, ArtifactID: v.ArtifactID,
		Version: 1, Comment: comment,
	}, approver)
	if err != nil {
		return nil, fmt.Errorf("approving %s: %w", v.ArtifactID, err)
	}
	return sealed, nil
}

func seedPrincipal(role authz.Role) authz.Principal {
	return authz.Principal{
		ID: types.PrincipalID(id.NewUUIDv7()), Kind: authz.KindUser,
		Grants: []authz.Grant{{Role: role}}, Permissions: authz.SetForRoles(role),
		AuthTime: time.Now(), AMR: []string{"pwd", "mfa"},
		Display: "seed:" + string(role),
	}
}
