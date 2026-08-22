// Package app holds the identity use cases: JIT provisioning, role resolution,
// role assignment and API key management.
package app

import (
	"context"
	"log/slog"
	"strings"
	"time"

	auditapp "github.com/specforge/specforge/internal/audit/app"
	auditdomain "github.com/specforge/specforge/internal/audit/domain"
	"github.com/specforge/specforge/internal/identity/domain"
	"github.com/specforge/specforge/internal/platform/authn"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/cache"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/id"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/outbox"
	"github.com/specforge/specforge/internal/platform/types"
)

// Repository is the identity persistence port.
type Repository interface {
	CreatePrincipal(ctx context.Context, tx db.Tx, p *domain.Principal) error
	UpdatePrincipal(ctx context.Context, tx db.Tx, p *domain.Principal) error
	GetPrincipal(ctx context.Context, tenantID types.TenantID, id types.PrincipalID) (*domain.Principal, error)
	FindPrincipalBySubject(ctx context.Context, issuer, subject string) (*domain.Principal, error)
	ListPrincipals(ctx context.Context, tenantID types.TenantID, limit int) ([]*domain.Principal, error)

	CreateRoleAssignment(ctx context.Context, tx db.Tx, r *domain.RoleAssignment) error
	DeleteRoleAssignment(ctx context.Context, tx db.Tx, tenantID types.TenantID, id string) error
	ListRoleAssignments(ctx context.Context, tenantID types.TenantID,
		principalID types.PrincipalID) ([]*domain.RoleAssignment, error)
	ReplaceRoleAssignments(ctx context.Context, tx db.Tx, tenantID types.TenantID,
		principalID types.PrincipalID, grants []domain.RoleAssignment) error

	CreateAPIKey(ctx context.Context, tx db.Tx, k *domain.APIKey) error
	FindAPIKey(ctx context.Context, keyID string) (*domain.APIKey, error)
	RevokeAPIKey(ctx context.Context, tx db.Tx, tenantID types.TenantID, keyID string) error
	TouchAPIKey(ctx context.Context, keyID string) error

	ListIdPMappings(ctx context.Context, tenantID types.TenantID) ([]domain.IdPRoleMapping, error)
	ReplaceIdPMappings(ctx context.Context, tx db.Tx, tenantID types.TenantID,
		mappings []domain.IdPRoleMapping) error
}

// Service is the identity application service.
type Service struct {
	db       *db.DB
	repo     Repository
	audit    *auditapp.Service
	outbox   outbox.Writer
	authz    *authz.Evaluator
	cache    cache.Cache
	cacheTTL time.Duration
	logger   *slog.Logger
	// designAuthority lists the principals on each tenant's Design Authority.
	// Phase 10 moves this into the governance module; the lookup is behind this
	// method now so the ABAC rule already works.
	designAuthority func(ctx context.Context, tenantID types.TenantID, p types.PrincipalID) bool
}

// NewService builds the identity service.
func NewService(database *db.DB, repo Repository, audit *auditapp.Service,
	ob outbox.Writer, ev *authz.Evaluator, c cache.Cache, ttl time.Duration,
	logger *slog.Logger) *Service {

	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &Service{
		db: database, repo: repo, audit: audit, outbox: ob, authz: ev,
		cache: c, cacheTTL: ttl, logger: logger,
		designAuthority: func(context.Context, types.TenantID, types.PrincipalID) bool { return false },
	}
}

// SetDesignAuthorityLookup wires the Design Authority membership check.
func (s *Service) SetDesignAuthorityLookup(
	fn func(ctx context.Context, tenantID types.TenantID, p types.PrincipalID) bool) {
	s.designAuthority = fn
}

// ResolveFromClaims turns verified token claims into an authorized principal.
//
// This is the just-in-time provisioning path: a user who authenticates for the
// first time gets a principal record and role grants derived from their identity
// provider groups. Unmapped groups grant nothing.
func (s *Service) ResolveFromClaims(ctx context.Context, claims *authn.Claims,
	tenantClaim, rolesClaim string) (authz.Principal, error) {

	const op = "identity.ResolveFromClaims"

	tenantValue := claims.String(tenantClaim)
	if tenantValue == "" {
		return authz.Principal{}, errors.Unauthorized(op, "auth.tenant_claim_missing",
			"The token does not identify a tenant.")
	}
	tenantID, err := types.ParseTenantID(tenantValue)
	if err != nil {
		return authz.Principal{}, errors.Unauthorized(op, "auth.tenant_claim_invalid",
			"The tenant claim is not a valid identifier.")
	}

	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: tenantID})

	principal, err := s.repo.FindPrincipalBySubject(ctx, claims.Issuer, claims.Subject)
	if err != nil && errors.KindOf(err) != errors.KindNotFound {
		return authz.Principal{}, err
	}

	groups := claims.StringSlice(rolesClaim)
	if len(groups) == 0 {
		groups = claims.StringSlice("groups")
	}

	if principal == nil {
		principal, err = s.provision(ctx, tenantID, claims, groups)
		if errors.KindOf(err) == errors.KindConflict {
			// Concurrent first sign-in. A browser that opens several requests at
			// once will race here, and every one of them will read "no such
			// principal" before any of them inserts. The unique constraint on
			// (issuer, subject) decides the winner; the losers re-read rather
			// than failing, because from the user's point of view this is one
			// sign-in, not a conflict they can do anything about.
			principal, err = s.repo.FindPrincipalBySubject(ctx, claims.Issuer, claims.Subject)
		}
		if err != nil {
			return authz.Principal{}, err
		}
		if principal == nil {
			return authz.Principal{}, errors.Internal(op, "principal.provision_failed",
				"The principal could not be provisioned or found after a concurrent sign-in.")
		}
	} else if principal.TenantID != tenantID {
		// The same subject cannot be reused across tenants: that would let an
		// identity provider move a user between isolation boundaries.
		return authz.Principal{}, errors.Forbidden(op, "authz.tenant_mismatch",
			"This identity belongs to a different tenant.")
	}

	if !principal.Active() {
		return authz.Principal{}, errors.Forbidden(op, "auth.principal_disabled",
			"This account is disabled.")
	}

	grants, err := s.grantsFor(ctx, tenantID, principal.ID)
	if err != nil {
		return authz.Principal{}, err
	}

	return authz.Principal{
		ID: principal.ID, Kind: principal.Kind, TenantID: tenantID,
		Subject: principal.Subject, Issuer: principal.Issuer,
		Display: principal.DisplayName, Email: principal.Email,
		Grants:          grants,
		Permissions:     authz.Resolve(grants, ""),
		AuthTime:        claims.AuthTimeOrIssued(),
		AMR:             claims.AMR,
		DesignAuthority: s.designAuthority(ctx, tenantID, principal.ID),
	}, nil
}

func (s *Service) provision(ctx context.Context, tenantID types.TenantID,
	claims *authn.Claims, groups []string) (*domain.Principal, error) {

	const op = "identity.provision"

	principalID := types.PrincipalID(id.NewUUIDv7())
	display := claims.Name
	if display == "" {
		display = claims.Email
	}
	p, err := domain.NewPrincipal(principalID, tenantID, authz.KindUser,
		claims.Issuer, claims.Subject, claims.Email, display)
	if err != nil {
		return nil, err
	}

	err = s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := s.repo.CreatePrincipal(ctx, tx, p); err != nil {
			return err
		}

		mappings, err := s.repo.ListIdPMappings(ctx, tenantID)
		if err != nil {
			return err
		}
		mapped := domain.MapGroups(groups, mappings)

		assignments := make([]domain.RoleAssignment, 0, len(mapped))
		for _, g := range mapped {
			assignments = append(assignments, domain.RoleAssignment{
				ID: id.NewUUIDv7(), TenantID: tenantID, PrincipalID: principalID,
				ProjectID: g.ProjectID, Role: g.Role,
				GrantedBy: principalID, GrantedAt: types.Now(),
			})
		}
		if len(assignments) > 0 {
			if err := s.repo.ReplaceRoleAssignments(ctx, tx, tenantID, principalID, assignments); err != nil {
				return err
			}
		}

		rec := auditdomain.New(tenantID, nil, "principal.provision",
			auditdomain.OutcomeSuccess, auditdomain.SeverityNotice,
			auditdomain.Actor{
				Kind: string(authz.KindSystem), PrincipalID: principalID,
				Subject: claims.Subject, Issuer: claims.Issuer,
			},
			auditdomain.Target{Type: "Principal", ID: principalID.String()}).
			WithAttr("issuer", claims.Issuer).
			WithAttr("groups", groups).
			WithAttr("mapped_roles", roleNames(mapped))
		if err := s.audit.Append(ctx, tx, rec); err != nil {
			return err
		}

		ev, err := outbox.New("principal.provisioned", tenantID, nil,
			outbox.Aggregate{Type: "Principal", ID: principalID.String()},
			outbox.Actor{Kind: string(authz.KindSystem), PrincipalID: principalID.String()},
			outbox.Correlation{},
			map[string]any{
				"principal_id": principalID.String(),
				"issuer":       claims.Issuer,
				"roles":        roleNames(mapped),
			})
		if err != nil {
			return errors.Wrap(err, op, errors.KindInternal, "principal.event_failed",
				"Could not record the principal provisioning event.")
		}
		return s.outbox.Append(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}

	obs.Counter("sf_principals_provisioned_total", "Principals provisioned on first login", nil)
	return p, nil
}

// grantsFor resolves a principal's grants, using a short-lived cache.
//
// The cache is invalidated by role.assignment.changed rather than only expiring,
// so a revoked role stops applying promptly instead of lingering for a TTL.
func (s *Service) grantsFor(ctx context.Context, tenantID types.TenantID,
	principalID types.PrincipalID) ([]authz.Grant, error) {

	key := cache.Key(tenantID, "grants", principalID.String())
	if raw, ok, _ := s.cache.Get(ctx, key); ok {
		if grants, err := decodeGrants(raw); err == nil {
			return grants, nil
		}
	}

	assignments, err := s.repo.ListRoleAssignments(ctx, tenantID, principalID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	grants := make([]authz.Grant, 0, len(assignments))
	for _, a := range assignments {
		if !a.Active(now) {
			continue
		}
		grants = append(grants, authz.Grant{Role: a.Role, ProjectID: a.ProjectID})
	}

	if raw, err := encodeGrants(grants); err == nil {
		_ = s.cache.Set(ctx, key, raw, s.cacheTTL)
	}
	return grants, nil
}

// InvalidateGrants clears a principal's cached permissions.
func (s *Service) InvalidateGrants(ctx context.Context, tenantID types.TenantID, principalID types.PrincipalID) {
	_ = s.cache.Delete(ctx, cache.Key(tenantID, "grants", principalID.String()))
}

// AssignRole grants a role.
func (s *Service) AssignRole(ctx context.Context, tenantID types.TenantID,
	principalID types.PrincipalID, role authz.Role, projectID string,
	expiresAt *time.Time, actor authz.Principal) (*domain.RoleAssignment, error) {

	const op = "identity.AssignRole"

	if err := s.authz.Require(actor, authz.RoleAssign, authz.Resource{
		Type: "role_assignment", TenantID: tenantID, ProjectID: projectID,
	}); err != nil {
		return nil, err
	}
	if !role.Valid() {
		return nil, errors.Invalid(op, "role.invalid", "Role %q is not recognised.", role)
	}

	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: tenantID, PrincipalID: actor.ID})

	assignment := &domain.RoleAssignment{
		ID: id.NewUUIDv7(), TenantID: tenantID, PrincipalID: principalID,
		ProjectID: projectID, Role: role, GrantedBy: actor.ID,
		GrantedAt: types.Now(), ExpiresAt: expiresAt,
	}

	err := s.db.Tx(ctx, func(ctx context.Context, tx db.Tx) error {
		if err := s.repo.CreateRoleAssignment(ctx, tx, assignment); err != nil {
			return err
		}
		rec := auditdomain.New(tenantID, nil, "role.assign",
			auditdomain.OutcomeSuccess, auditdomain.SeverityWarning,
			auditActor(actor),
			auditdomain.Target{Type: "RoleAssignment", ID: assignment.ID}).
			WithAttr("principal_id", principalID.String()).
			WithAttr("role", string(role)).
			WithAttr("project_id", projectID)
		if err := s.audit.Append(ctx, tx, rec); err != nil {
			return err
		}
		ev, err := outbox.New("role.assignment.changed", tenantID, nil,
			outbox.Aggregate{Type: "Principal", ID: principalID.String()},
			outbox.Actor{Kind: string(actor.Kind), PrincipalID: actor.ID.String()},
			outbox.Correlation{},
			map[string]any{
				"principal_id": principalID.String(),
				"added":        []string{string(role)},
				"project_id":   projectID,
			})
		if err != nil {
			return errors.Wrap(err, op, errors.KindInternal, "role.event_failed",
				"Could not record the role assignment event.")
		}
		return s.outbox.Append(ctx, tx, ev)
	})
	if err != nil {
		return nil, err
	}

	s.InvalidateGrants(ctx, tenantID, principalID)
	return assignment, nil
}

// AuthenticateAPIKey verifies a presented API key.
func (s *Service) AuthenticateAPIKey(ctx context.Context, presented string) (authz.Principal, error) {
	const op = "identity.AuthenticateAPIKey"

	keyID, secret, ok := domain.ParseAPIKey(presented)
	if !ok {
		return authz.Principal{}, errors.Unauthorized(op, "auth.api_key_malformed",
			"The API key is not in the expected format.")
	}

	key, err := s.repo.FindAPIKey(ctx, keyID)
	if err != nil {
		// Do not distinguish "unknown key" from "wrong secret": that difference
		// is an enumeration oracle.
		return authz.Principal{}, errors.Unauthorized(op, "auth.api_key_invalid",
			"The API key is not valid.")
	}
	if err := key.Verify(secret, time.Now()); err != nil {
		return authz.Principal{}, err
	}

	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: key.TenantID})

	principal, err := s.repo.GetPrincipal(ctx, key.TenantID, key.PrincipalID)
	if err != nil {
		return authz.Principal{}, err
	}
	if !principal.Active() {
		return authz.Principal{}, errors.Forbidden(op, "auth.principal_disabled",
			"This account is disabled.")
	}

	set, err := authz.FromNames(key.Permissions)
	if err != nil {
		return authz.Principal{}, errors.Internal(op, "apikey.permissions_invalid",
			"The API key carries an unrecognised permission.")
	}

	go func() { _ = s.repo.TouchAPIKey(context.Background(), keyID) }()

	return authz.Principal{
		ID: principal.ID, Kind: authz.KindServiceAccount, TenantID: key.TenantID,
		Display: key.Name, Subject: principal.Subject, Issuer: "specforge:apikey",
		// Clamped again here even though NewAPIKey refuses approval permissions:
		// defence in depth against a key created before a rule changed.
		Permissions: authz.ServiceAccountSet(set),
		AuthTime:    time.Now(),
	}, nil
}

// ListPrincipals returns the tenant's principals.
func (s *Service) ListPrincipals(ctx context.Context, tenantID types.TenantID,
	actor authz.Principal) ([]*domain.Principal, error) {

	if err := s.authz.Require(actor, authz.PrincipalRead, authz.Resource{
		Type: "principal", TenantID: tenantID,
	}); err != nil {
		return nil, err
	}
	ctx = db.WithTenant(ctx, db.TenantContext{TenantID: tenantID, PrincipalID: actor.ID})
	return s.repo.ListPrincipals(ctx, tenantID, 200)
}

// SeedIdPMappings installs the default group-to-role mapping for a tenant.
func (s *Service) SeedIdPMappings(ctx context.Context, tx db.Tx, tenantID types.TenantID,
	by types.PrincipalID) error {

	mappings := make([]domain.IdPRoleMapping, 0, len(authz.AllRoles()))
	for _, r := range authz.AllRoles() {
		mappings = append(mappings, domain.IdPRoleMapping{
			ID: id.NewUUIDv7(), TenantID: tenantID, IdPGroup: string(r),
			Role: r, MappingVersion: 1, CreatedBy: by, CreatedAt: types.Now(),
		})
	}
	return s.repo.ReplaceIdPMappings(ctx, tx, tenantID, mappings)
}

func roleNames(grants []authz.Grant) []string {
	out := make([]string, 0, len(grants))
	for _, g := range grants {
		out = append(out, string(g.Role))
	}
	return out
}

func auditActor(p authz.Principal) auditdomain.Actor {
	return auditdomain.Actor{
		Kind: string(p.Kind), PrincipalID: p.ID, Display: p.Display,
		Subject: p.Subject, Issuer: p.Issuer, BreakGlass: p.BreakGlass,
	}
}

func encodeGrants(grants []authz.Grant) ([]byte, error) {
	var sb strings.Builder
	for i, g := range grants {
		if i > 0 {
			sb.WriteByte('\n')
		}
		sb.WriteString(string(g.Role))
		sb.WriteByte('|')
		sb.WriteString(g.ProjectID)
	}
	return []byte(sb.String()), nil
}

func decodeGrants(raw []byte) ([]authz.Grant, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []authz.Grant
	for _, line := range strings.Split(string(raw), "\n") {
		role, project, ok := strings.Cut(line, "|")
		if !ok {
			return nil, errors.New("identity: malformed cached grant")
		}
		r, err := authz.ParseRole(role)
		if err != nil {
			return nil, err
		}
		out = append(out, authz.Grant{Role: r, ProjectID: project})
	}
	return out, nil
}
