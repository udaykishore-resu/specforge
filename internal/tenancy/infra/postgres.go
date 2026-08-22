// Package infra implements the tenancy repositories against PostgreSQL.
package infra

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/fsm"
	"github.com/specforge/specforge/internal/platform/types"
	"github.com/specforge/specforge/internal/tenancy/app"
	"github.com/specforge/specforge/internal/tenancy/domain"
)

// TenantRepo persists tenants.
type TenantRepo struct{ db *db.DB }

var _ app.TenantRepository = (*TenantRepo)(nil)

// NewTenantRepo builds the repository.
func NewTenantRepo(database *db.DB) *TenantRepo { return &TenantRepo{db: database} }

const tenantColumns = `id, slug, name, status, status_reason, isolation_mode, region,
       settings, created_by, created_at, updated_at, version_no`

func scanTenant(scan func(...any) error) (*domain.Tenant, error) {
	var (
		t           domain.Tenant
		id, mode    string
		status      string
		settingsRaw []byte
		createdBy   string
		createdAt   time.Time
		updatedAt   time.Time
	)
	if err := scan(&id, &t.Slug, &t.Name, &status, &t.StatusReason, &mode, &t.Region,
		&settingsRaw, &createdBy, &createdAt, &updatedAt, &t.Version); err != nil {
		return nil, err
	}
	t.ID = types.TenantID(id)
	t.Status = fsm.State(status)
	t.IsolationMode = types.IsolationMode(mode)
	t.CreatedBy = types.PrincipalID(createdBy)
	t.CreatedAt = createdAt.UTC()
	t.UpdatedAt = updatedAt.UTC()

	if len(settingsRaw) > 0 {
		if err := json.Unmarshal(settingsRaw, &t.Settings); err != nil {
			return nil, fmt.Errorf("tenancy: decoding tenant settings: %w", err)
		}
	}
	return &t, nil
}

// Create inserts a tenant.
func (r *TenantRepo) Create(ctx context.Context, tx db.Tx, t *domain.Tenant) error {
	const op = "tenancy.CreateTenant"

	settings, err := json.Marshal(t.Settings)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "tenant.encode_failed",
			"Could not encode the tenant settings.")
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO tenants (id, slug, name, status, status_reason, isolation_mode, region,
		                     settings, created_by, created_at, updated_at, version_no)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12)`,
		t.ID.String(), t.Slug, t.Name, string(t.Status), t.StatusReason,
		string(t.IsolationMode), t.Region, string(settings),
		t.CreatedBy.String(), t.CreatedAt, t.UpdatedAt, t.Version)

	if err != nil {
		if db.IsUniqueViolation(err) {
			return errors.Conflict(op, "tenant.slug_taken",
				"The slug %q is already in use.", t.Slug)
		}
		return errors.Wrap(err, op, errors.KindUnavailable, "tenant.create_failed",
			"Could not create the tenant.")
	}
	return nil
}

// Update writes a tenant with optimistic concurrency.
func (r *TenantRepo) Update(ctx context.Context, tx db.Tx, t *domain.Tenant) error {
	const op = "tenancy.UpdateTenant"

	settings, err := json.Marshal(t.Settings)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "tenant.encode_failed",
			"Could not encode the tenant settings.")
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE tenants
		   SET name = $2, status = $3, status_reason = $4, region = $5,
		       settings = $6::jsonb, updated_at = now(), version_no = version_no + 1
		 WHERE id = $1 AND version_no = $7`,
		t.ID.String(), t.Name, string(t.Status), t.StatusReason, t.Region,
		string(settings), t.Version)
	if err != nil {
		return errors.Wrap(err, op, errors.KindUnavailable, "tenant.update_failed",
			"Could not update the tenant.")
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return errors.Conflict(op, "concurrency.stale_version",
			"The tenant was modified by another request. Reload and try again.")
	}
	t.Version++
	return nil
}

// GetByID loads a tenant.
func (r *TenantRepo) GetByID(ctx context.Context, id types.TenantID) (*domain.Tenant, error) {
	const op = "tenancy.GetTenant"

	// The tenants table is platform-scoped, so this read goes through the pool
	// directly rather than a tenant-scoped transaction. The caller has already
	// been authorized for this specific tenant id.
	row := r.db.SQL().QueryRowContext(ctx,
		`SELECT `+tenantColumns+` FROM tenants WHERE id = $1`, id.String())
	t, err := scanTenant(row.Scan)
	if db.IsNoRows(err) {
		return nil, errors.NotFound(op, "tenant.not_found", "The tenant was not found.")
	}
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindUnavailable, "tenant.read_failed",
			"Could not read the tenant.")
	}
	return t, nil
}

// GetBySlug loads a tenant by slug.
func (r *TenantRepo) GetBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	const op = "tenancy.GetTenantBySlug"

	row := r.db.SQL().QueryRowContext(ctx,
		`SELECT `+tenantColumns+` FROM tenants WHERE slug = $1`, strings.ToLower(slug))
	t, err := scanTenant(row.Scan)
	if db.IsNoRows(err) {
		return nil, errors.NotFound(op, "tenant.not_found", "The tenant was not found.")
	}
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindUnavailable, "tenant.read_failed",
			"Could not read the tenant.")
	}
	return t, nil
}

// List returns tenants matching a filter.
func (r *TenantRepo) List(ctx context.Context, f app.TenantFilter) ([]*domain.Tenant, string, error) {
	const op = "tenancy.ListTenants"

	conds := []string{"1=1"}
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}

	if f.Status != "" {
		add("status = $%d", string(f.Status))
	}
	if f.Slug != "" {
		add("slug = $%d", strings.ToLower(f.Slug))
	}
	if len(f.Scope) > 0 {
		ids := make([]string, len(f.Scope))
		for i, t := range f.Scope {
			ids[i] = t.String()
		}
		// A scoped caller only sees their own tenants; this is the query-level
		// half of the isolation rule, with RLS covering everything else.
		placeholders := make([]string, len(ids))
		for i, v := range ids {
			args = append(args, v)
			placeholders[i] = fmt.Sprintf("$%d", len(args))
		}
		conds = append(conds, "id IN ("+strings.Join(placeholders, ",")+")")
	}
	if f.Cursor != "" {
		created, err := decodeTimeCursor(f.Cursor)
		if err != nil {
			return nil, "", errors.Invalid(op, "tenant.invalid_cursor",
				"The pagination cursor is not valid.")
		}
		add("created_at < $%d", created)
	}

	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args = append(args, int64(limit+1))

	query := `SELECT ` + tenantColumns + ` FROM tenants WHERE ` +
		strings.Join(conds, " AND ") +
		fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, len(args))

	rows, err := r.db.SQL().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, "", errors.Wrap(err, op, errors.KindUnavailable, "tenant.read_failed",
			"Could not list tenants.")
	}
	defer func() { _ = rows.Close() }()

	var out []*domain.Tenant
	for rows.Next() {
		t, err := scanTenant(rows.Scan)
		if err != nil {
			return nil, "", errors.Wrap(err, op, errors.KindInternal, "tenant.decode_failed",
				"Could not decode a tenant record.")
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, "", errors.Wrap(err, op, errors.KindUnavailable, "tenant.read_failed",
			"Could not list tenants.")
	}

	var next string
	if len(out) > limit {
		out = out[:limit]
		next = encodeTimeCursor(out[len(out)-1].CreatedAt)
	}
	return out, next, nil
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

// ProjectRepo persists projects.
type ProjectRepo struct{ db *db.DB }

var _ app.ProjectRepository = (*ProjectRepo)(nil)

// NewProjectRepo builds the repository.
func NewProjectRepo(database *db.DB) *ProjectRepo { return &ProjectRepo{db: database} }

const projectColumns = `tenant_id, id, key, name, description, status, pdlc_phase,
       settings, graph_version, created_by, created_at, updated_at, version_no`

func scanProject(scan func(...any) error) (*domain.Project, error) {
	var (
		p           domain.Project
		tenantID    string
		projectID   string
		status      string
		phase       string
		settingsRaw []byte
		createdBy   string
		createdAt   time.Time
		updatedAt   time.Time
	)
	if err := scan(&tenantID, &projectID, &p.Key, &p.Name, &p.Description, &status, &phase,
		&settingsRaw, &p.GraphVersion, &createdBy, &createdAt, &updatedAt, &p.Version); err != nil {
		return nil, err
	}
	p.TenantID = types.TenantID(tenantID)
	p.ID = types.ProjectID(projectID)
	p.Status = fsm.State(status)
	p.Phase = domain.PDLCPhase(phase)
	p.CreatedBy = types.PrincipalID(createdBy)
	p.CreatedAt = createdAt.UTC()
	p.UpdatedAt = updatedAt.UTC()

	if len(settingsRaw) > 0 {
		if err := json.Unmarshal(settingsRaw, &p.Settings); err != nil {
			return nil, fmt.Errorf("tenancy: decoding project settings: %w", err)
		}
	}
	return &p, nil
}

// Create inserts a project.
func (r *ProjectRepo) Create(ctx context.Context, tx db.Tx, p *domain.Project) error {
	const op = "tenancy.CreateProject"

	settings, err := json.Marshal(p.Settings)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "project.encode_failed",
			"Could not encode the project settings.")
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO projects (tenant_id, id, key, name, description, status, pdlc_phase,
		                      settings, graph_version, created_by, created_at, updated_at, version_no)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11,$12,$13)`,
		p.TenantID.String(), p.ID.String(), p.Key, p.Name, p.Description,
		string(p.Status), string(p.Phase), string(settings), p.GraphVersion,
		p.CreatedBy.String(), p.CreatedAt, p.UpdatedAt, p.Version)

	if err != nil {
		if db.IsUniqueViolation(err) {
			return errors.Conflict(op, "project.key_taken",
				"The project key %q is already used in this tenant.", p.Key)
		}
		return errors.Wrap(err, op, errors.KindUnavailable, "project.create_failed",
			"Could not create the project.")
	}
	return nil
}

// Update writes a project with optimistic concurrency.
func (r *ProjectRepo) Update(ctx context.Context, tx db.Tx, p *domain.Project) error {
	const op = "tenancy.UpdateProject"

	settings, err := json.Marshal(p.Settings)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "project.encode_failed",
			"Could not encode the project settings.")
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE projects
		   SET name = $3, description = $4, status = $5, pdlc_phase = $6,
		       settings = $7::jsonb, updated_at = now(), version_no = version_no + 1
		 WHERE tenant_id = $1 AND id = $2 AND version_no = $8`,
		p.TenantID.String(), p.ID.String(), p.Name, p.Description,
		string(p.Status), string(p.Phase), string(settings), p.Version)
	if err != nil {
		return errors.Wrap(err, op, errors.KindUnavailable, "project.update_failed",
			"Could not update the project.")
	}
	n, err := res.RowsAffected()
	if err == nil && n == 0 {
		return errors.Conflict(op, "concurrency.stale_version",
			"The project was modified by another request. Reload and try again.")
	}
	p.Version++
	return nil
}

// GetByID loads a project.
func (r *ProjectRepo) GetByID(ctx context.Context, tenantID types.TenantID, id types.ProjectID) (*domain.Project, error) {
	const op = "tenancy.GetProject"

	var p *domain.Project
	err := r.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT `+projectColumns+` FROM projects WHERE tenant_id = $1 AND id = $2`,
			tenantID.String(), id.String())
		got, err := scanProject(row.Scan)
		if db.IsNoRows(err) {
			return errors.NotFound(op, "project.not_found", "The project was not found.")
		}
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "project.read_failed",
				"Could not read the project.")
		}
		p = got
		return nil
	})
	return p, err
}

// GetByKey loads a project by its key.
func (r *ProjectRepo) GetByKey(ctx context.Context, tenantID types.TenantID, key string) (*domain.Project, error) {
	const op = "tenancy.GetProjectByKey"

	var p *domain.Project
	err := r.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT `+projectColumns+` FROM projects WHERE tenant_id = $1 AND key = $2`,
			tenantID.String(), strings.ToUpper(key))
		got, err := scanProject(row.Scan)
		if db.IsNoRows(err) {
			return errors.NotFound(op, "project.not_found", "The project was not found.")
		}
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "project.read_failed",
				"Could not read the project.")
		}
		p = got
		return nil
	})
	return p, err
}

// List returns projects in a tenant.
func (r *ProjectRepo) List(ctx context.Context, f app.ProjectFilter) ([]*domain.Project, string, error) {
	const op = "tenancy.ListProjects"

	conds := []string{"tenant_id = $1"}
	args := []any{f.TenantID.String()}
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.Status != "" {
		add("status = $%d", string(f.Status))
	}
	if f.Phase != "" {
		add("pdlc_phase = $%d", string(f.Phase))
	}
	if f.Cursor != "" {
		created, err := decodeTimeCursor(f.Cursor)
		if err != nil {
			return nil, "", errors.Invalid(op, "project.invalid_cursor",
				"The pagination cursor is not valid.")
		}
		add("created_at < $%d", created)
	}

	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args = append(args, int64(limit+1))

	query := `SELECT ` + projectColumns + ` FROM projects WHERE ` +
		strings.Join(conds, " AND ") +
		fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, len(args))

	var out []*domain.Project
	err := r.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "project.read_failed",
				"Could not list projects.")
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			p, err := scanProject(rows.Scan)
			if err != nil {
				return errors.Wrap(err, op, errors.KindInternal, "project.decode_failed",
					"Could not decode a project record.")
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", err
	}

	var next string
	if len(out) > limit {
		out = out[:limit]
		next = encodeTimeCursor(out[len(out)-1].CreatedAt)
	}
	return out, next, nil
}

// BumpGraphVersion increments the project's graph version.
//
// Cache keys embed this value, so incrementing it inside the same transaction as
// a graph write makes invalidation atomic with the write. A separate cache
// delete could be lost between commit and invalidation; this cannot.
func (r *ProjectRepo) BumpGraphVersion(ctx context.Context, tx db.Tx,
	tenantID types.TenantID, id types.ProjectID) (int64, error) {

	var v int64
	err := tx.QueryRowContext(ctx, `
		UPDATE projects SET graph_version = graph_version + 1, updated_at = now()
		 WHERE tenant_id = $1 AND id = $2
		 RETURNING graph_version`, tenantID.String(), id.String()).Scan(&v)
	if err != nil {
		return 0, errors.Wrap(err, "tenancy.BumpGraphVersion", errors.KindUnavailable,
			"project.graph_version_failed", "Could not advance the project graph version.")
	}
	return v, nil
}

func encodeTimeCursor(t time.Time) string {
	return base64.RawURLEncoding.EncodeToString([]byte("t" + t.UTC().Format(time.RFC3339Nano)))
}

func decodeTimeCursor(c string) (time.Time, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil || len(raw) < 2 || raw[0] != 't' {
		return time.Time{}, fmt.Errorf("tenancy: malformed cursor")
	}
	return time.Parse(time.RFC3339Nano, string(raw[1:]))
}
