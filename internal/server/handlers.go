package server

import (
	"encoding/json"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	artifactapp "github.com/specforge/specforge/internal/artifactgraph/app"
	artifactdomain "github.com/specforge/specforge/internal/artifactgraph/domain"
	auditapp "github.com/specforge/specforge/internal/audit/app"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/fsm"
	"github.com/specforge/specforge/internal/platform/httpx"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/types"
	tenancyapp "github.com/specforge/specforge/internal/tenancy/app"
	tenancydomain "github.com/specforge/specforge/internal/tenancy/domain"
)

// ---------------------------------------------------------------------------
// Health, readiness, metrics, discovery
// ---------------------------------------------------------------------------

// handleHealthz reports process liveness only.
//
// It deliberately checks nothing external: a liveness probe that fails when a
// dependency is down causes Kubernetes to restart healthy pods during an outage,
// which turns a degradation into an outage.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	s.ok(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz checks the dependencies this instance needs to serve traffic and
// names the failing one, so a probe failure is diagnosable from its own output.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	checks := map[string]string{}
	healthy := true

	if err := s.db.Health(ctx); err != nil {
		checks["database"] = err.Error()
		healthy = false
	} else {
		checks["database"] = "ok"
	}

	if s.cache != nil {
		if err := s.cache.Health(ctx); err != nil {
			checks["cache"] = err.Error()
			healthy = false
		} else {
			checks["cache"] = "ok"
		}
	}

	if !s.isReady() {
		checks["server"] = "starting"
		healthy = false
	} else {
		checks["server"] = "ok"
	}

	status := http.StatusOK
	if !healthy {
		status = http.StatusServiceUnavailable
	}
	s.ok(w, r, status, map[string]any{"ready": healthy, "checks": checks})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.db.RecordPoolMetrics()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(obs.Gather()))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	info := map[string]any{
		"service": s.cfg.ServiceName,
		"version": s.cfg.Version,
		"env":     string(s.cfg.Env),
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		info["go"] = bi.GoVersion
		for _, setting := range bi.Settings {
			if setting.Key == "vcs.revision" {
				info["commit"] = setting.Value
			}
		}
	}
	s.ok(w, r, http.StatusOK, info)
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	routes := s.Routes()
	out := make([]map[string]any, 0, len(routes))
	for _, rt := range routes {
		entry := map[string]any{"method": rt.Method, "path": rt.Pattern}
		if rt.Public {
			entry["auth"] = "public"
		} else {
			entry["permission"] = rt.Permission
		}
		out = append(out, entry)
	}
	s.ok(w, r, http.StatusOK, map[string]any{
		"service": s.cfg.ServiceName,
		"version": "v1",
		"routes":  out,
		"note":    "The full OpenAPI 3.1 document is served from api/openapi/specforge.v1.yaml.",
	})
}

// handleMe returns the caller's identity and effective permissions.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	roles := make([]map[string]string, 0, len(p.Grants))
	for _, g := range p.Grants {
		roles = append(roles, map[string]string{"role": string(g.Role), "project_id": g.ProjectID})
	}
	s.ok(w, r, http.StatusOK, map[string]any{
		"principal_id":     p.ID.String(),
		"kind":             string(p.Kind),
		"tenant_id":        p.TenantID.String(),
		"display":          p.Display,
		"email":            p.Email,
		"roles":            roles,
		"permissions":      p.Permissions.Names(),
		"auth_time":        p.AuthTime.UTC(),
		"mfa":              p.HasMFA(),
		"design_authority": p.DesignAuthority,
	})
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

type createTenantRequest struct {
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	IsolationMode string `json:"isolation_mode"`
	Region        string `json:"region"`
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	body, err := readBody(r, s.cfg.HTTP.MaxBodyBytes)
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.body_too_large", "The request body is too large."))
		return
	}
	var req createTenantRequest
	if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	mode := types.IsolationMode(req.IsolationMode)
	if mode == "" {
		mode = types.IsolationShared
	}

	s.idempotent(w, r, body, func() (int, any, error) {
		tenant, err := s.tenancy.CreateTenant(r.Context(), tenancyapp.CreateTenantInput{
			Slug: req.Slug, Name: req.Name, IsolationMode: mode, Region: req.Region,
		}, actor)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, tenantDTO(tenant), nil
	})
}

func (s *Server) handleListTenants(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenants, next, err := s.tenancy.ListTenants(r.Context(), tenancyapp.TenantFilter{
		Cursor: r.URL.Query().Get("cursor"),
		Limit:  intParam(r, "limit", s.cfg.Limits.DefaultPageSize),
	}, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]any, 0, len(tenants))
	for _, t := range tenants {
		out = append(out, tenantDTO(t))
	}
	s.ok(w, r, http.StatusOK, map[string]any{"items": out, "next_cursor": next})
}

func (s *Server) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	tenant, err := s.tenancy.GetTenant(r.Context(), tenantID, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, tenantDTO(tenant))
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	var settings tenancydomain.Settings
	if err := httpx.DecodeJSON(w, r, &settings, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	tenant, err := s.tenancy.UpdateSettings(r.Context(), tenantID, settings, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, tenantDTO(tenant))
}

type reasonRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleSuspendTenant(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	var req reasonRequest
	if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.tenancy.Suspend(r.Context(), tenantID, req.Reason, actor); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, map[string]string{"status": "SUSPENDED"})
}

func (s *Server) handleReinstateTenant(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	if err := s.tenancy.Reinstate(r.Context(), tenantID, actor); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, map[string]string{"status": "ACTIVE"})
}

// ---------------------------------------------------------------------------
// Principals
// ---------------------------------------------------------------------------

func (s *Server) handleListPrincipals(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	principals, err := s.identity.ListPrincipals(r.Context(), tenantID, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(principals))
	for _, p := range principals {
		out = append(out, map[string]any{
			"principal_id": p.ID.String(),
			"kind":         string(p.Kind),
			"display":      p.DisplayName,
			"email":        p.Email,
			"status":       p.Status,
			"created_at":   p.CreatedAt,
		})
	}
	s.ok(w, r, http.StatusOK, map[string]any{"items": out})
}

type assignRoleRequest struct {
	Role      string     `json:"role"`
	ProjectID string     `json:"project_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (s *Server) handleAssignRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	principalID, err := types.ParsePrincipalID(r.PathValue("principalID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_principal_id",
			"The principal identifier is not valid."))
		return
	}
	var req assignRoleRequest
	if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	role, err := authz.ParseRole(req.Role)
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "role.invalid", "%s", err.Error()))
		return
	}
	assignment, err := s.identity.AssignRole(r.Context(), tenantID, principalID,
		role, req.ProjectID, req.ExpiresAt, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusCreated, map[string]any{
		"id": assignment.ID, "role": string(assignment.Role),
		"project_id": assignment.ProjectID, "granted_at": assignment.GrantedAt,
	})
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

type createProjectRequest struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	body, _ := readBody(r, s.cfg.HTTP.MaxBodyBytes)
	var req createProjectRequest
	if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}

	s.idempotent(w, r, body, func() (int, any, error) {
		project, err := s.tenancy.CreateProject(r.Context(), tenancyapp.CreateProjectInput{
			TenantID: tenantID, Key: req.Key, Name: req.Name, Description: req.Description,
		}, actor)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, projectDTO(project), nil
	})
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	projects, next, err := s.tenancy.ListProjects(r.Context(), tenancyapp.ProjectFilter{
		TenantID: tenantID,
		Status:   fsm.State(r.URL.Query().Get("status")),
		Cursor:   r.URL.Query().Get("cursor"),
		Limit:    intParam(r, "limit", s.cfg.Limits.DefaultPageSize),
	}, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]any, 0, len(projects))
	for _, p := range projects {
		out = append(out, projectDTO(p))
	}
	s.ok(w, r, http.StatusOK, map[string]any{"items": out, "next_cursor": next})
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	project, err := s.tenancy.GetProject(r.Context(), tenantID, projectID, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, projectDTO(project))
}

func (s *Server) handleArchiveProject(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.tenancy.ArchiveProject(r.Context(), tenantID, projectID, actor); err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, map[string]string{"status": "ARCHIVED"})
}

// ---------------------------------------------------------------------------
// Artifacts
// ---------------------------------------------------------------------------

type createArtifactRequest struct {
	ArtifactID    string            `json:"artifact_id,omitempty"`
	Area          string            `json:"area,omitempty"`
	Type          string            `json:"type"`
	Title         string            `json:"title"`
	ContentSchema string            `json:"content_schema,omitempty"`
	Content       json.RawMessage   `json:"content"`
	Labels        map[string]string `json:"labels,omitempty"`
	Source        *artifactRefDTO   `json:"source,omitempty"`
	Parent        *artifactRefDTO   `json:"parent,omitempty"`
	Generator     *generatorDTO     `json:"generator,omitempty"`
}

type artifactRefDTO struct {
	ArtifactID string `json:"artifact_id"`
	Version    int    `json:"version"`
}

type generatorDTO struct {
	Kind                  string `json:"kind"`
	PromptVersion         string `json:"prompt_version,omitempty"`
	Model                 string `json:"model,omitempty"`
	Provider              string `json:"provider,omitempty"`
	GuardrailChainVersion string `json:"guardrail_chain_version,omitempty"`
	InferenceID           string `json:"inference_id,omitempty"`
	Analyzer              string `json:"analyzer,omitempty"`
	AnalyzerVersion       string `json:"analyzer_version,omitempty"`
}

func (g *generatorDTO) toDomain() artifactdomain.Generator {
	if g == nil {
		return artifactdomain.Generator{Kind: types.GeneratedByUser}
	}
	return artifactdomain.Generator{
		Kind:                  types.GeneratorKind(g.Kind),
		PromptVersion:         g.PromptVersion,
		Model:                 g.Model,
		Provider:              g.Provider,
		GuardrailChainVersion: g.GuardrailChainVersion,
		InferenceID:           g.InferenceID,
		Analyzer:              g.Analyzer,
		AnalyzerVersion:       g.AnalyzerVersion,
	}
}

func (a *artifactRefDTO) toDomain() *types.ArtifactRef {
	if a == nil {
		return nil
	}
	return &types.ArtifactRef{
		ArtifactID: types.ArtifactID(a.ArtifactID), Version: a.Version,
	}
}

func (s *Server) handleCreateArtifact(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	body, _ := readBody(r, s.cfg.HTTP.MaxBodyBytes)
	var req createArtifactRequest
	if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	artifactType, err := types.ParseArtifactType(req.Type)
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "artifact.type_invalid", "%s", err.Error()))
		return
	}

	s.idempotent(w, r, body, func() (int, any, error) {
		v, err := s.artifacts.Create(r.Context(), artifactapp.CreateInput{
			TenantID: tenantID, ProjectID: projectID,
			ArtifactID: types.ArtifactID(req.ArtifactID), Area: strings.ToUpper(req.Area),
			Type: artifactType, Title: req.Title,
			ContentSchema: req.ContentSchema, Content: req.Content,
			Generator: req.Generator.toDomain(), Labels: req.Labels,
			Parent: req.Parent.toDomain(), Source: req.Source.toDomain(),
		}, actor)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, versionDTO(v), nil
	})
}

func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f := artifactapp.ArtifactFilter{
		TenantID: tenantID, ProjectID: projectID,
		Type:   types.ArtifactType(r.URL.Query().Get("type")),
		Status: fsm.State(r.URL.Query().Get("status")),
		Cursor: r.URL.Query().Get("cursor"),
		Limit:  intParam(r, "limit", s.cfg.Limits.DefaultPageSize),
	}
	artifacts, next, err := s.artifacts.List(r.Context(), f, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]any, 0, len(artifacts))
	for _, a := range artifacts {
		out = append(out, artifactDTO(a))
	}
	s.ok(w, r, http.StatusOK, map[string]any{"items": out, "next_cursor": next})
}

func (s *Server) handleGetArtifact(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	artifactID := types.ArtifactID(r.PathValue("artifactID"))
	artifact, versions, err := s.artifacts.GetArtifact(r.Context(), tenantID, projectID, artifactID, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	history := make([]any, 0, len(versions))
	for _, v := range versions {
		history = append(history, versionDTO(v))
	}
	s.ok(w, r, http.StatusOK, map[string]any{
		"artifact": artifactDTO(artifact), "versions": history,
	})
}

func (s *Server) handleGetVersion(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	artifactID := types.ArtifactID(r.PathValue("artifactID"))
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_version",
			"The version must be an integer."))
		return
	}
	v, err := s.artifacts.GetVersion(r.Context(), tenantID, projectID, artifactID, version, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, versionDTO(v))
}

type updateDraftRequest struct {
	Content   json.RawMessage `json:"content"`
	VersionNo int64           `json:"version_no,omitempty"`
}

func (s *Server) handleUpdateDraft(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	artifactID := types.ArtifactID(r.PathValue("artifactID"))
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_version",
			"The version must be an integer."))
		return
	}
	var req updateDraftRequest
	if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}
	// If-Match carries the optimistic concurrency token when the client sends it.
	if im := r.Header.Get("If-Match"); im != "" && req.VersionNo == 0 {
		if n, convErr := strconv.ParseInt(strings.Trim(im, `"`), 10, 64); convErr == nil {
			req.VersionNo = n
		}
	}

	v, err := s.artifacts.UpdateDraft(r.Context(), tenantID, projectID, artifactID,
		version, req.Content, req.VersionNo, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, versionDTO(v))
}

type commentRequest struct {
	Comment string `json:"comment"`
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	s.transition(w, r, artifactdomain.EventSubmitForReview)
}

func (s *Server) handleRequestChanges(w http.ResponseWriter, r *http.Request) {
	s.transition(w, r, artifactdomain.EventRequestChanges)
}

func (s *Server) handleFreeze(w http.ResponseWriter, r *http.Request) {
	s.transition(w, r, artifactdomain.EventFreeze)
}

func (s *Server) transition(w http.ResponseWriter, r *http.Request, event fsm.Event) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	artifactID := types.ArtifactID(r.PathValue("artifactID"))
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_version",
			"The version must be an integer."))
		return
	}
	var req commentRequest
	if r.ContentLength > 0 {
		if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	v, err := s.artifacts.Transition(r.Context(), tenantID, projectID, artifactID,
		version, event, req.Comment, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, versionDTO(v))
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	artifactID := types.ArtifactID(r.PathValue("artifactID"))
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_version",
			"The version must be an integer."))
		return
	}
	body, _ := readBody(r, s.cfg.HTTP.MaxBodyBytes)
	var req commentRequest
	if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}

	s.idempotent(w, r, body, func() (int, any, error) {
		v, err := s.artifacts.Approve(r.Context(), artifactapp.ApproveInput{
			TenantID: tenantID, ProjectID: projectID, ArtifactID: artifactID,
			Version: version, Comment: req.Comment,
		}, actor)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, versionDTO(v), nil
	})
}

type reviseRequest struct {
	ChangeSummary string `json:"change_summary"`
}

func (s *Server) handleRevise(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	artifactID := types.ArtifactID(r.PathValue("artifactID"))
	body, _ := readBody(r, s.cfg.HTTP.MaxBodyBytes)
	var req reviseRequest
	if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
		s.fail(w, r, err)
		return
	}

	s.idempotent(w, r, body, func() (int, any, error) {
		v, err := s.artifacts.Revise(r.Context(), tenantID, projectID, artifactID,
			req.ChangeSummary, actor)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, versionDTO(v), nil
	})
}

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, projectID, err := s.scope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	artifactID := types.ArtifactID(r.PathValue("artifactID"))
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_version",
			"The version must be an integer."))
		return
	}
	body, err := s.artifacts.Evidence(r.Context(), tenantID, projectID, artifactID, version, actor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.specforge.approval+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// scope resolves the tenant and project from the path.
func (s *Server) scope(r *http.Request) (types.TenantID, types.ProjectID, error) {
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		return "", "", errors.Invalid("server.scope", "request.invalid_tenant_id",
			"The tenant identifier is not valid.")
	}
	projectID, err := types.ParseProjectID(r.PathValue("projectID"))
	if err != nil {
		return "", "", errors.Invalid("server.scope", "request.invalid_project_id",
			"The project identifier is not valid.")
	}
	return tenantID, projectID, nil
}

func intParam(r *http.Request, name string, def int) int {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	if err := s.authz.Require(actor, authz.AuditRead, authz.Resource{
		Type: "audit", TenantID: tenantID,
	}); err != nil {
		s.fail(w, r, err)
		return
	}

	f := auditapp.Filter{
		TenantID: tenantID,
		Action:   r.URL.Query().Get("action"),
		Outcome:  r.URL.Query().Get("outcome"),
		Severity: r.URL.Query().Get("severity"),
		Cursor:   r.URL.Query().Get("cursor"),
		Limit:    intParam(r, "limit", s.cfg.Limits.DefaultPageSize),
	}
	if a := r.URL.Query().Get("actor"); a != "" {
		f.Actor = types.PrincipalID(a)
	}

	records, next, err := s.audit.List(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]any, 0, len(records))
	for _, rec := range records {
		out = append(out, auditDTO(rec))
	}
	s.ok(w, r, http.StatusOK, map[string]any{"items": out, "next_cursor": next})
}

func (s *Server) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	if err := s.authz.Require(actor, authz.AuditRead, authz.Resource{
		Type: "audit", TenantID: tenantID,
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	seq, err := strconv.ParseInt(r.PathValue("sequence"), 10, 64)
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_sequence",
			"The sequence must be an integer."))
		return
	}
	rec, err := s.audit.Get(r.Context(), tenantID, seq)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, auditDTO(rec))
}

type verifyAuditRequest struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	if err := s.authz.Require(actor, authz.AuditRead, authz.Resource{
		Type: "audit", TenantID: tenantID,
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	var req verifyAuditRequest
	if r.ContentLength > 0 {
		if err := httpx.DecodeJSON(w, r, &req, s.cfg.HTTP.MaxBodyBytes); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	report, err := s.audit.Verify(r.Context(), tenantID, req.From, req.To)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.ok(w, r, http.StatusOK, map[string]any{
		"tenant_id":       report.TenantID.String(),
		"from":            report.From,
		"to":              report.To,
		"records_checked": report.RecordsChecked,
		"valid":           report.Valid,
		"failed_at":       report.FailedAt,
		"reason":          report.Reason,
	})
}

func (s *Server) handleAnchorAudit(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.principalOf(w, r)
	if !ok {
		return
	}
	tenantID, err := types.ParseTenantID(r.PathValue("tenantID"))
	if err != nil {
		s.fail(w, r, errors.Invalid("server", "request.invalid_tenant_id",
			"The tenant identifier is not valid."))
		return
	}
	if err := s.authz.Require(actor, authz.AuditExport, authz.Resource{
		Type: "audit", TenantID: tenantID,
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	anchor, err := s.audit.Anchor(r.Context(), tenantID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if anchor == nil {
		s.ok(w, r, http.StatusOK, map[string]string{"status": "nothing_to_anchor"})
		return
	}
	s.ok(w, r, http.StatusCreated, anchor)
}
