// Package infra implements the identity repository against PostgreSQL.
package infra

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/identity/app"
	"github.com/specforge/specforge/internal/identity/domain"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/db/pgwire"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/types"
)

// Postgres is the identity repository.
type Postgres struct{ db *db.DB }

var _ app.Repository = (*Postgres)(nil)

// NewPostgres builds the repository.
func NewPostgres(database *db.DB) *Postgres { return &Postgres{db: database} }

const principalColumns = `id, tenant_id, kind, issuer, subject, email, display_name,
       status, attributes, last_login_at, created_at, updated_at, version_no`

func scanPrincipal(scan func(...any) error) (*domain.Principal, error) {
	var (
		p         domain.Principal
		pid       string
		tenantID  string
		kind      string
		attrsRaw  []byte
		lastLogin *time.Time
		createdAt time.Time
		updatedAt time.Time
	)
	if err := scan(&pid, &tenantID, &kind, &p.Issuer, &p.Subject, &p.Email,
		&p.DisplayName, &p.Status, &attrsRaw, &lastLogin,
		&createdAt, &updatedAt, &p.Version); err != nil {
		return nil, err
	}
	p.ID = types.PrincipalID(pid)
	p.TenantID = types.TenantID(tenantID)
	p.Kind = authz.PrincipalKind(kind)
	p.CreatedAt = createdAt.UTC()
	p.UpdatedAt = updatedAt.UTC()
	if lastLogin != nil {
		t := lastLogin.UTC()
		p.LastLoginAt = &t
	}
	p.Attributes = map[string]any{}
	if len(attrsRaw) > 0 {
		_ = json.Unmarshal(attrsRaw, &p.Attributes)
	}
	return &p, nil
}

// CreatePrincipal inserts a principal.
func (r *Postgres) CreatePrincipal(ctx context.Context, tx db.Tx, p *domain.Principal) error {
	const op = "identity.CreatePrincipal"

	attrs, err := json.Marshal(p.Attributes)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "principal.encode_failed",
			"Could not encode the principal attributes.")
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO principals (id, tenant_id, kind, issuer, subject, email, display_name,
		                        status, attributes, created_at, updated_at, version_no)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12)`,
		p.ID.String(), p.TenantID.String(), string(p.Kind), p.Issuer, p.Subject,
		p.Email, p.DisplayName, p.Status, string(attrs),
		p.CreatedAt, p.UpdatedAt, p.Version)

	if err != nil {
		if db.IsUniqueViolation(err) {
			return errors.Conflict(op, "principal.already_exists",
				"A principal already exists for this identity.")
		}
		return errors.Wrap(err, op, errors.KindUnavailable, "principal.create_failed",
			"Could not create the principal.")
	}
	return nil
}

// UpdatePrincipal writes a principal.
func (r *Postgres) UpdatePrincipal(ctx context.Context, tx db.Tx, p *domain.Principal) error {
	const op = "identity.UpdatePrincipal"

	attrs, err := json.Marshal(p.Attributes)
	if err != nil {
		return errors.Wrap(err, op, errors.KindInternal, "principal.encode_failed",
			"Could not encode the principal attributes.")
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE principals
		   SET email = $2, display_name = $3, status = $4, attributes = $5::jsonb,
		       last_login_at = $6, updated_at = now(), version_no = version_no + 1
		 WHERE id = $1 AND version_no = $7`,
		p.ID.String(), p.Email, p.DisplayName, p.Status, string(attrs),
		p.LastLoginAt, p.Version)
	if err != nil {
		return errors.Wrap(err, op, errors.KindUnavailable, "principal.update_failed",
			"Could not update the principal.")
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.Conflict(op, "concurrency.stale_version",
			"The principal was modified by another request.")
	}
	p.Version++
	return nil
}

// GetPrincipal loads a principal.
func (r *Postgres) GetPrincipal(ctx context.Context, tenantID types.TenantID,
	id types.PrincipalID) (*domain.Principal, error) {

	const op = "identity.GetPrincipal"

	var p *domain.Principal
	err := r.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		row := tx.QueryRowContext(ctx,
			`SELECT `+principalColumns+` FROM principals WHERE tenant_id = $1 AND id = $2`,
			tenantID.String(), id.String())
		got, err := scanPrincipal(row.Scan)
		if db.IsNoRows(err) {
			return errors.NotFound(op, "principal.not_found", "The principal was not found.")
		}
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "principal.read_failed",
				"Could not read the principal.")
		}
		p = got
		return nil
	})
	return p, err
}

// FindPrincipalBySubject resolves an identity-provider subject.
//
// This read is deliberately not tenant-scoped: at login time the tenant is not
// yet established, and the caller compares the returned tenant with the token's
// tenant claim before trusting anything. The principals table is queried through
// the pool for that reason, and only ever by (issuer, subject).
func (r *Postgres) FindPrincipalBySubject(ctx context.Context, issuer, subject string) (*domain.Principal, error) {
	const op = "identity.FindPrincipalBySubject"

	row := r.db.SQL().QueryRowContext(ctx,
		`SELECT `+principalColumns+` FROM principals WHERE issuer = $1 AND subject = $2`,
		issuer, subject)
	p, err := scanPrincipal(row.Scan)
	if db.IsNoRows(err) {
		return nil, errors.NotFound(op, "principal.not_found", "The principal was not found.")
	}
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindUnavailable, "principal.read_failed",
			"Could not read the principal.")
	}
	return p, nil
}

// ListPrincipals returns a tenant's principals.
func (r *Postgres) ListPrincipals(ctx context.Context, tenantID types.TenantID, limit int) ([]*domain.Principal, error) {
	const op = "identity.ListPrincipals"

	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var out []*domain.Principal
	err := r.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx,
			`SELECT `+principalColumns+` FROM principals
			  WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2`,
			tenantID.String(), int64(limit))
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "principal.read_failed",
				"Could not list principals.")
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			p, err := scanPrincipal(rows.Scan)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Role assignments
// ---------------------------------------------------------------------------

// CreateRoleAssignment grants a role.
func (r *Postgres) CreateRoleAssignment(ctx context.Context, tx db.Tx, a *domain.RoleAssignment) error {
	const op = "identity.CreateRoleAssignment"

	var projectID any
	if a.ProjectID != "" {
		projectID = a.ProjectID
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO role_assignments (tenant_id, id, principal_id, project_id, role,
		                              granted_by, granted_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.TenantID.String(), a.ID, a.PrincipalID.String(), projectID, string(a.Role),
		a.GrantedBy.String(), a.GrantedAt, a.ExpiresAt)

	if err != nil {
		if db.IsUniqueViolation(err) {
			return errors.Conflict(op, "role.already_granted",
				"That role is already granted at this scope.")
		}
		return errors.Wrap(err, op, errors.KindUnavailable, "role.grant_failed",
			"Could not grant the role.")
	}
	return nil
}

// DeleteRoleAssignment revokes a role.
func (r *Postgres) DeleteRoleAssignment(ctx context.Context, tx db.Tx,
	tenantID types.TenantID, id string) error {

	_, err := tx.ExecContext(ctx,
		`DELETE FROM role_assignments WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id)
	if err != nil {
		return errors.Wrap(err, "identity.DeleteRoleAssignment", errors.KindUnavailable,
			"role.revoke_failed", "Could not revoke the role.")
	}
	return nil
}

// ListRoleAssignments returns a principal's grants.
func (r *Postgres) ListRoleAssignments(ctx context.Context, tenantID types.TenantID,
	principalID types.PrincipalID) ([]*domain.RoleAssignment, error) {

	const op = "identity.ListRoleAssignments"

	var out []*domain.RoleAssignment
	err := r.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, tenant_id, principal_id, coalesce(project_id::text, ''), role,
			       granted_by, granted_at, expires_at
			  FROM role_assignments
			 WHERE tenant_id = $1 AND principal_id = $2`,
			tenantID.String(), principalID.String())
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "role.read_failed",
				"Could not read role assignments.")
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var (
				a         domain.RoleAssignment
				tid       string
				pid       string
				role      string
				grantedBy string
				grantedAt time.Time
			)
			if err := rows.Scan(&a.ID, &tid, &pid, &a.ProjectID, &role,
				&grantedBy, &grantedAt, &a.ExpiresAt); err != nil {
				return err
			}
			a.TenantID = types.TenantID(tid)
			a.PrincipalID = types.PrincipalID(pid)
			a.Role = authz.Role(role)
			a.GrantedBy = types.PrincipalID(grantedBy)
			a.GrantedAt = grantedAt.UTC()
			out = append(out, &a)
		}
		return rows.Err()
	})
	return out, err
}

// ReplaceRoleAssignments sets a principal's grants to exactly the list given.
func (r *Postgres) ReplaceRoleAssignments(ctx context.Context, tx db.Tx,
	tenantID types.TenantID, principalID types.PrincipalID, grants []domain.RoleAssignment) error {

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM role_assignments WHERE tenant_id = $1 AND principal_id = $2`,
		tenantID.String(), principalID.String()); err != nil {
		return errors.Wrap(err, "identity.ReplaceRoleAssignments", errors.KindUnavailable,
			"role.replace_failed", "Could not replace the role assignments.")
	}
	for i := range grants {
		if err := r.CreateRoleAssignment(ctx, tx, &grants[i]); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// API keys
// ---------------------------------------------------------------------------

// CreateAPIKey stores a key.
func (r *Postgres) CreateAPIKey(ctx context.Context, tx db.Tx, k *domain.APIKey) error {
	const op = "identity.CreateAPIKey"

	var projectID any
	if k.ProjectID != "" {
		projectID = k.ProjectID
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO api_keys (tenant_id, id, key_id, principal_id, name, secret_hash,
		                      permissions, project_id, created_by, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7::text[],$8,$9,$10,$11)`,
		k.TenantID.String(), k.ID, k.KeyID, k.PrincipalID.String(), k.Name, k.SecretHash,
		pgwire.TextArray(k.Permissions), projectID, k.CreatedBy.String(),
		k.CreatedAt, k.ExpiresAt)

	if err != nil {
		if db.IsCheckViolation(err) {
			// The database refuses approval permissions on a service credential.
			return errors.Forbidden(op, "sod.violation",
				"An API key cannot hold approval permissions.")
		}
		if db.IsUniqueViolation(err) {
			return errors.Conflict(op, "apikey.duplicate", "That key identifier is already in use.")
		}
		return errors.Wrap(err, op, errors.KindUnavailable, "apikey.create_failed",
			"Could not create the API key.")
	}
	return nil
}

// FindAPIKey resolves a key by its public identifier.
func (r *Postgres) FindAPIKey(ctx context.Context, keyID string) (*domain.APIKey, error) {
	const op = "identity.FindAPIKey"

	// Not tenant-scoped for the same reason as FindPrincipalBySubject: the tenant
	// is derived from the key, not supplied by the caller.
	row := r.db.SQL().QueryRowContext(ctx, `
		SELECT tenant_id, id, key_id, principal_id, name, secret_hash,
		       permissions::text, coalesce(project_id::text, ''), created_by,
		       created_at, expires_at, revoked_at, last_used_at
		  FROM api_keys WHERE key_id = $1`, keyID)

	var (
		k        domain.APIKey
		tenantID string
		pid      string
		perms    string
		by       string
	)
	err := row.Scan(&tenantID, &k.ID, &k.KeyID, &pid, &k.Name, &k.SecretHash,
		&perms, &k.ProjectID, &by, &k.CreatedAt, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt)
	if db.IsNoRows(err) {
		return nil, errors.NotFound(op, "apikey.not_found", "The API key was not found.")
	}
	if err != nil {
		return nil, errors.Wrap(err, op, errors.KindUnavailable, "apikey.read_failed",
			"Could not read the API key.")
	}
	k.TenantID = types.TenantID(tenantID)
	k.PrincipalID = types.PrincipalID(pid)
	k.CreatedBy = types.PrincipalID(by)
	k.Permissions = pgwire.ParseTextArray(perms)
	return &k, nil
}

// RevokeAPIKey marks a key revoked.
func (r *Postgres) RevokeAPIKey(ctx context.Context, tx db.Tx, tenantID types.TenantID, keyID string) error {
	_, err := tx.ExecContext(ctx,
		`UPDATE api_keys SET revoked_at = now() WHERE tenant_id = $1 AND key_id = $2`,
		tenantID.String(), keyID)
	if err != nil {
		return errors.Wrap(err, "identity.RevokeAPIKey", errors.KindUnavailable,
			"apikey.revoke_failed", "Could not revoke the API key.")
	}
	return nil
}

// TouchAPIKey records last use, for stale-credential reporting.
func (r *Postgres) TouchAPIKey(ctx context.Context, keyID string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := r.db.SQL().ExecContext(ctx,
		`UPDATE api_keys SET last_used_at = now() WHERE key_id = $1`, keyID)
	return err
}

// ---------------------------------------------------------------------------
// Identity provider mappings
// ---------------------------------------------------------------------------

// ListIdPMappings returns a tenant's group-to-role mappings.
func (r *Postgres) ListIdPMappings(ctx context.Context, tenantID types.TenantID) ([]domain.IdPRoleMapping, error) {
	const op = "identity.ListIdPMappings"

	var out []domain.IdPRoleMapping
	err := r.db.ReadOnly(ctx, func(ctx context.Context, tx db.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, tenant_id, idp_group, role, coalesce(project_key, ''),
			       mapping_version, created_by, created_at
			  FROM idp_role_mappings WHERE tenant_id = $1`, tenantID.String())
		if err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "idpmapping.read_failed",
				"Could not read the identity provider mappings.")
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				m         domain.IdPRoleMapping
				tid       string
				role      string
				createdBy string
				version   int64
			)
			if err := rows.Scan(&m.ID, &tid, &m.IdPGroup, &role, &m.ProjectKey,
				&version, &createdBy, &m.CreatedAt); err != nil {
				return err
			}
			m.TenantID = types.TenantID(tid)
			m.Role = authz.Role(strings.ToLower(role))
			m.MappingVersion = int(version)
			m.CreatedBy = types.PrincipalID(createdBy)
			out = append(out, m)
		}
		return rows.Err()
	})
	return out, err
}

// ReplaceIdPMappings sets a tenant's mappings.
func (r *Postgres) ReplaceIdPMappings(ctx context.Context, tx db.Tx,
	tenantID types.TenantID, mappings []domain.IdPRoleMapping) error {

	const op = "identity.ReplaceIdPMappings"

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM idp_role_mappings WHERE tenant_id = $1`, tenantID.String()); err != nil {
		return errors.Wrap(err, op, errors.KindUnavailable, "idpmapping.replace_failed",
			"Could not replace the identity provider mappings.")
	}
	for _, m := range mappings {
		var projectKey any
		if m.ProjectKey != "" {
			projectKey = m.ProjectKey
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO idp_role_mappings (tenant_id, id, idp_group, role, project_key,
			                               mapping_version, created_by, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			m.TenantID.String(), m.ID, m.IdPGroup, string(m.Role), projectKey,
			int64(m.MappingVersion), m.CreatedBy.String(), m.CreatedAt); err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "idpmapping.replace_failed",
				"Could not write an identity provider mapping.")
		}
	}
	return nil
}
