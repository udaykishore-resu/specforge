// Package app holds the tenancy use cases.
package app

import (
	"context"
	"log/slog"

	auditapp "github.com/specforge/specforge/internal/audit/app"
	auditdomain "github.com/specforge/specforge/internal/audit/domain"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/fsm"
	"github.com/specforge/specforge/internal/platform/id"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/outbox"
	"github.com/specforge/specforge/internal/platform/types"
	"github.com/specforge/specforge/internal/tenancy/domain"
)

// TenantRepository persists tenants.
type TenantRepository interface {
	Create(ctx context.Context, tx db.Tx, t *domain.Tenant) error
	Update(ctx context.Context, tx db.Tx, t *domain.Tenant) error
	GetByID(ctx context.Context, id types.TenantID) (*domain.Tenant, error)
	GetBySlug(ctx context.Context, slug string) (*domain.Tenant, error)
	List(ctx context.Context, f TenantFilter) ([]*domain.Tenant, string, error)
}

// ProjectRepository persists projects.
type ProjectRepository interface {
	Create(ctx context.Context, tx db.Tx, p *domain.Project) error
	Update(ctx context.Context, tx db.Tx, p *domain.Project) error
	GetByID(ctx context.Context, tenantID types.TenantID, id types.ProjectID) (*domain.Project, error)
	GetByKey(ctx context.Context, tenantID types.TenantID, key string) (*domain.Project, error)
	List(ctx context.Context, f ProjectFilter) ([]*domain.Project, string, error)
	BumpGraphVersion(ctx context.Context, tx db.Tx, tenantID types.TenantID, id types.ProjectID) (int64, error)
}

// TenantFilter narrows a tenant query.
type TenantFilter struct {
	Status fsm.State
	Slug   string
	Cursor string
	Limit  int
	// Scope restricts results to tenants the caller belongs to. Empty means
	// platform-wide, which requires tenant:read at platform scope.
	Scope []types.TenantID
}

// ProjectFilter narrows a project query.
type ProjectFilter struct {
	TenantID types.TenantID
	Status   fsm.State
	Phase    domain.PDLCPhase
	Cursor   string
	Limit    int
}

// Provisioner establishes a tenant's isolation resources.
type Provisioner interface {
	Provision(ctx context.Context, t *domain.Tenant) error
	Deprovision(ctx context.Context, t *domain.Tenant) error
}

// Service is the tenancy application service.
type Service struct {
	db       *db.DB
	tenants  TenantRepository
	projects ProjectRepository
	audit    *auditapp.Service
	outbox   outbox.Writer
	authz    *authz.Evaluator
	logger   *slog.Logger
}

// NewService builds the tenancy service.
func NewService(database *db.DB, tenants TenantRepository, projects ProjectRepository,
	audit *auditapp.Service, ob outbox.Writer, ev *authz.Evaluator, logger *slog.Logger) *Service {
	return &Service{
		db: database, tenants: tenants, projects: projects,
		audit: audit, outbox: ob, authz: ev, logger: logger,
	}
}

// CreateTenantInput is the create-tenant command.
type CreateTenantInput struct {
	Slug          string
	Name          string
	IsolationMode types.IsolationMode
	Region        string
}

// CreateTenant creates a tenant in PROVISIONING and records the intent.
//
// Provisioning itself happens asynchronously, driven by the tenant.created
// event. Doing it inline would mean a slow bucket or key creation could leave a
// committed tenant row with no isolation resources behind it.
func (s *Service) CreateTenant(ctx context.Context, in CreateTenantInput, actor authz.Principal) (*domain.Tenant, error) {
	const op = "tenancy.CreateTenant"

	tenantID := types.TenantID(id.NewUUIDv7())
	tenant, err := domain.NewTenant(tenantID, in.Slug, in.Name, in.IsolationMode, in.Region, actor.ID)
	if err != nil {
		return nil, err
	}

	// Creating a tenant is a platform operation, so the transaction runs in the
	// new tenant's own scope: every row it writes belongs to that tenant.
	ctx = db.WithTenant(ctx, db.TenantContext{
		TenantID: tenantID, PrincipalID: actor.ID, IsolationMode: in.IsolationMode,
	})

	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := s.tenants.Create(ctx, tx, tenant); err != nil {
			return err
		}
		if err := s.audit.EnsureChain(ctx, tx, tenantID); err != nil {
			return err
		}

		rec := auditdomain.New(tenantID, nil, "tenant.create",
			auditdomain.OutcomeSuccess, auditdomain.SeverityNotice,
			actorOf(actor), auditdomain.Target{Type: "Tenant", ID: tenantID.String()}).
			WithAttr("slug", tenant.Slug).
			WithAttr("isolation_mode", string(tenant.IsolationMode)).
			WithAttr("region", tenant.Region)
		if err := s.audit.Append(ctx, tx, rec); err != nil {
			return err
		}

		ev, err := outbox.New("tenant.created", tenantID, nil,
			outbox.Aggregate{Type: "Tenant", ID: tenantID.String()},
			outboxActor(actor), correlationFrom(ctx),
			map[string]any{
				"tenant_id": tenantID.String(), "slug": tenant.Slug,
				"name": tenant.Name, "isolation_mode": string(tenant.IsolationMode),
				"region": tenant.Region,
			})
		if err != nil {
			return errors.Wrap(err, op, errors.KindInternal, "tenant.event_failed",
				"Could not record the tenant creation event.")
		}
		return s.outbox.Append(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}

	obs.Counter("sf_tenants_created_total", "Tenants created", nil)
	s.logger.InfoContext(ctx, "tenant created",
		"tenant_id", tenantID, "slug", tenant.Slug, "isolation_mode", tenant.IsolationMode)
	return tenant, nil
}

// MarkProvisioned transitions a tenant to ACTIVE once its resources exist.
func (s *Service) MarkProvisioned(ctx context.Context, tenantID types.TenantID) error {
	return s.transitionTenant(ctx, tenantID, domain.EventProvisioned, "",
		authz.Principal{ID: types.PrincipalID(systemPrincipal), Kind: authz.KindSystem, TenantID: tenantID})
}

// MarkProvisionFailed records a failed provisioning attempt.
func (s *Service) MarkProvisionFailed(ctx context.Context, tenantID types.TenantID, reason string) error {
	return s.transitionTenant(ctx, tenantID, domain.EventProvisionFailed, reason,
		authz.Principal{ID: types.PrincipalID(systemPrincipal), Kind: authz.KindSystem, TenantID: tenantID})
}

// Suspend blocks writes for a tenant.
func (s *Service) Suspend(ctx context.Context, tenantID types.TenantID, reason string, actor authz.Principal) error {
	return s.transitionTenant(ctx, tenantID, domain.EventSuspend, reason, actor)
}

// Reinstate restores a suspended tenant.
func (s *Service) Reinstate(ctx context.Context, tenantID types.TenantID, actor authz.Principal) error {
	return s.transitionTenant(ctx, tenantID, domain.EventReinstate, "", actor)
}

// RequestDeletion moves a tenant into DEPROVISIONING.
func (s *Service) RequestDeletion(ctx context.Context, tenantID types.TenantID, reason string, actor authz.Principal) error {
	return s.transitionTenant(ctx, tenantID, domain.EventRequestDeletion, reason, actor)
}

func (s *Service) transitionTenant(ctx context.Context, tenantID types.TenantID,
	event fsm.Event, reason string, actor authz.Principal) error {

	const op = "tenancy.transitionTenant"

	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: tenantID, PrincipalID: actor.ID})

	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		tenant, err := s.tenants.GetByID(ctx, tenantID)
		if err != nil {
			return err
		}
		if reason != "" {
			tenant.StatusReason = reason
		}

		check := func(ctx context.Context, permission string) error {
			p, err := authz.ParsePermission(permission)
			if err != nil {
				return errors.Internal(op, "authz.unknown_permission",
					"Transition declares unknown permission %q.", permission)
			}
			return s.authz.Require(actor, p, authz.Resource{
				Type: "tenant", ID: tenantID.String(), TenantID: tenantID,
			})
		}
		// System transitions are driven by the platform's own provisioning
		// worker and carry no user permission.
		if actor.Kind == authz.KindSystem {
			check = nil
		}

		out, err := domain.TenantMachine.Fire(ctx, tenant.Status, event, tenant, check)
		if err != nil {
			return err
		}
		tenant.Status = out.To
		tenant.UpdatedAt = types.Now()

		if err := s.tenants.Update(ctx, tx, tenant); err != nil {
			return err
		}

		rec := auditdomain.New(tenantID, nil, out.AuditAction,
			auditdomain.OutcomeSuccess, severityFor(out.To),
			actorOf(actor), auditdomain.Target{Type: "Tenant", ID: tenantID.String()}).
			WithAttr("from", string(out.From)).
			WithAttr("to", string(out.To)).
			WithAttr("reason", reason)
		if err := s.audit.Append(ctx, tx, rec); err != nil {
			return err
		}

		ev, err := outbox.New(out.EmitEvent, tenantID, nil,
			outbox.Aggregate{Type: "Tenant", ID: tenantID.String()},
			outboxActor(actor), correlationFrom(ctx),
			map[string]any{
				"tenant_id": tenantID.String(),
				"from":      string(out.From), "to": string(out.To), "reason": reason,
			})
		if err != nil {
			return errors.Wrap(err, op, errors.KindInternal, "tenant.event_failed",
				"Could not record the tenant lifecycle event.")
		}
		return s.outbox.Append(ctx, tx, ev)
	})
}

// UpdateSettings replaces a tenant's settings.
func (s *Service) UpdateSettings(ctx context.Context, tenantID types.TenantID,
	settings domain.Settings, actor authz.Principal) (*domain.Tenant, error) {

	const op = "tenancy.UpdateSettings"

	if err := s.authz.Require(actor, authz.TenantUpdate, authz.Resource{
		Type: "tenant", ID: tenantID.String(), TenantID: tenantID,
	}); err != nil {
		return nil, err
	}

	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: tenantID, PrincipalID: actor.ID})

	var updated *domain.Tenant
	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		tenant, err := s.tenants.GetByID(ctx, tenantID)
		if err != nil {
			return err
		}
		before := tenant.Settings
		if err := tenant.UpdateSettings(settings); err != nil {
			return err
		}
		if err := s.tenants.Update(ctx, tx, tenant); err != nil {
			return err
		}

		// The audit record captures which keys changed, not their values, since
		// settings can carry configuration a reader is not entitled to see.
		rec := auditdomain.New(tenantID, nil, "tenant.settings.update",
			auditdomain.OutcomeSuccess, auditdomain.SeverityNotice,
			actorOf(actor), auditdomain.Target{Type: "TenantSettings", ID: tenantID.String()}).
			WithAttr("changed_keys", changedSettingKeys(before, settings))
		if err := s.audit.Append(ctx, tx, rec); err != nil {
			return err
		}

		ev, err := outbox.New("tenant.settings.updated", tenantID, nil,
			outbox.Aggregate{Type: "Tenant", ID: tenantID.String()},
			outboxActor(actor), correlationFrom(ctx),
			map[string]any{
				"tenant_id":    tenantID.String(),
				"changed_keys": changedSettingKeys(before, settings),
			})
		if err != nil {
			return errors.Wrap(err, op, errors.KindInternal, "tenant.event_failed",
				"Could not record the settings change event.")
		}
		if err := s.outbox.Append(ctx, tx, ev); err != nil {
			return err
		}
		updated = tenant
		return nil
	})
	return updated, err
}

// GetTenant returns a tenant.
func (s *Service) GetTenant(ctx context.Context, tenantID types.TenantID, actor authz.Principal) (*domain.Tenant, error) {
	if err := s.authz.Require(actor, authz.TenantRead, authz.Resource{
		Type: "tenant", ID: tenantID.String(), TenantID: tenantID,
	}); err != nil {
		return nil, err
	}
	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: tenantID, PrincipalID: actor.ID})
	return s.tenants.GetByID(ctx, tenantID)
}

// ListTenants returns the tenants the caller can see.
func (s *Service) ListTenants(ctx context.Context, f TenantFilter, actor authz.Principal) ([]*domain.Tenant, string, error) {
	// A caller without platform-wide tenant:read only ever sees their own tenant.
	if !actor.Permissions.Has(authz.TenantRead) {
		return nil, "", errors.Forbidden("tenancy.ListTenants", "authz.denied",
			"The tenant:read permission is required.")
	}
	if actor.Kind != authz.KindSystem && !actor.Permissions.Has(authz.TenantCreate) {
		f.Scope = []types.TenantID{actor.TenantID}
	}
	return s.tenants.List(ctx, f)
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

// CreateProjectInput is the create-project command.
type CreateProjectInput struct {
	TenantID    types.TenantID
	Key         string
	Name        string
	Description string
}

// CreateProject creates a project inside an active tenant.
func (s *Service) CreateProject(ctx context.Context, in CreateProjectInput, actor authz.Principal) (*domain.Project, error) {
	const op = "tenancy.CreateProject"

	if err := s.authz.Require(actor, authz.ProjectCreate, authz.Resource{
		Type: "project", TenantID: in.TenantID,
	}); err != nil {
		return nil, err
	}

	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: in.TenantID, PrincipalID: actor.ID})

	tenant, err := s.tenants.GetByID(ctx, in.TenantID)
	if err != nil {
		return nil, err
	}
	if !tenant.AcceptsWrites() {
		return nil, errors.Precondition(op, "tenant.not_active",
			"The tenant is %s and does not accept changes.", tenant.Status)
	}

	projectID := types.ProjectID(id.NewUUIDv7())
	project, err := domain.NewProject(in.TenantID, projectID, in.Key, in.Name, in.Description, actor.ID)
	if err != nil {
		return nil, err
	}

	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := s.projects.Create(ctx, tx, project); err != nil {
			return err
		}

		rec := auditdomain.New(in.TenantID, &projectID, "project.create",
			auditdomain.OutcomeSuccess, auditdomain.SeverityNotice,
			actorOf(actor), auditdomain.Target{
				Type: "Project", ID: projectID.String(), ProjectID: projectID.String(),
			}).
			WithAttr("key", project.Key).
			WithAttr("name", project.Name)
		if err := s.audit.Append(ctx, tx, rec); err != nil {
			return err
		}

		ev, err := outbox.New("project.created", in.TenantID, &projectID,
			outbox.Aggregate{Type: "Project", ID: projectID.String()},
			outboxActor(actor), correlationFrom(ctx),
			map[string]any{
				"tenant_id": in.TenantID.String(), "project_id": projectID.String(),
				"key": project.Key, "name": project.Name, "phase": string(project.Phase),
			})
		if err != nil {
			return errors.Wrap(err, op, errors.KindInternal, "project.event_failed",
				"Could not record the project creation event.")
		}
		return s.outbox.Append(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}

	obs.Counter("sf_projects_created_total", "Projects created", nil)
	return project, nil
}

// GetProject returns a project.
func (s *Service) GetProject(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID, actor authz.Principal) (*domain.Project, error) {

	if err := s.authz.Require(actor, authz.ProjectRead, authz.Resource{
		Type: "project", ID: projectID.String(), TenantID: tenantID, ProjectID: projectID.String(),
	}); err != nil {
		return nil, err
	}
	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: tenantID, PrincipalID: actor.ID})
	return s.projects.GetByID(ctx, tenantID, projectID)
}

// ListProjects returns a tenant's projects.
func (s *Service) ListProjects(ctx context.Context, f ProjectFilter, actor authz.Principal) ([]*domain.Project, string, error) {
	if err := s.authz.Require(actor, authz.ProjectRead, authz.Resource{
		Type: "project", TenantID: f.TenantID,
	}); err != nil {
		return nil, "", err
	}
	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: f.TenantID, PrincipalID: actor.ID})
	return s.projects.List(ctx, f)
}

// ArchiveProject archives a project.
func (s *Service) ArchiveProject(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID, actor authz.Principal) error {
	return s.transitionProject(ctx, tenantID, projectID, domain.EventArchive, actor)
}

// RestoreProject restores an archived project.
func (s *Service) RestoreProject(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID, actor authz.Principal) error {
	return s.transitionProject(ctx, tenantID, projectID, domain.EventRestore, actor)
}

func (s *Service) transitionProject(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID, event fsm.Event, actor authz.Principal) error {

	const op = "tenancy.transitionProject"

	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: tenantID, PrincipalID: actor.ID})

	return s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		project, err := s.projects.GetByID(ctx, tenantID, projectID)
		if err != nil {
			return err
		}

		check := func(ctx context.Context, permission string) error {
			p, err := authz.ParsePermission(permission)
			if err != nil {
				return errors.Internal(op, "authz.unknown_permission",
					"Transition declares unknown permission %q.", permission)
			}
			return s.authz.Require(actor, p, authz.Resource{
				Type: "project", ID: projectID.String(),
				TenantID: tenantID, ProjectID: projectID.String(),
				CreatedBy: project.CreatedBy,
			})
		}

		out, err := domain.ProjectMachine.Fire(ctx, project.Status, event, project, check)
		if err != nil {
			return err
		}
		project.Status = out.To
		project.UpdatedAt = types.Now()

		if err := s.projects.Update(ctx, tx, project); err != nil {
			return err
		}

		rec := auditdomain.New(tenantID, &projectID, out.AuditAction,
			auditdomain.OutcomeSuccess, auditdomain.SeverityNotice,
			actorOf(actor), auditdomain.Target{
				Type: "Project", ID: projectID.String(), ProjectID: projectID.String(),
			}).
			WithAttr("from", string(out.From)).
			WithAttr("to", string(out.To))
		if err := s.audit.Append(ctx, tx, rec); err != nil {
			return err
		}

		ev, err := outbox.New(out.EmitEvent, tenantID, &projectID,
			outbox.Aggregate{Type: "Project", ID: projectID.String()},
			outboxActor(actor), correlationFrom(ctx),
			map[string]any{
				"tenant_id": tenantID.String(), "project_id": projectID.String(),
				"from": string(out.From), "to": string(out.To),
			})
		if err != nil {
			return errors.Wrap(err, op, errors.KindInternal, "project.event_failed",
				"Could not record the project lifecycle event.")
		}
		return s.outbox.Append(ctx, tx, ev)
	})
}
