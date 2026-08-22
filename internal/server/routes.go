package server

import (
	"net/http"

	"github.com/specforge/specforge/internal/platform/authz"
)

// registerRoutes declares the API surface.
//
// Every entry names the permission it requires. The registration helper refuses
// to accept a handler without one, and `make lint-routes` fails the build if a
// route ever slips through with an unset permission.
func (s *Server) registerRoutes() {
	// --- Public: liveness, readiness, metrics and discovery -----------------
	s.PublicRoute(http.MethodGet, "/healthz", s.handleHealthz)
	s.PublicRoute(http.MethodGet, "/readyz", s.handleReadyz)
	s.PublicRoute(http.MethodGet, "/metrics", s.handleMetrics)
	s.PublicRoute(http.MethodGet, "/api/v1/version", s.handleVersion)
	s.PublicRoute(http.MethodGet, "/api/v1/openapi.json", s.handleOpenAPI)

	// --- Session ------------------------------------------------------------
	s.Route(http.MethodGet, "/api/v1/auth/me", authz.TenantRead, s.handleMe)

	// --- Tenants ------------------------------------------------------------
	s.Route(http.MethodPost, "/api/v1/tenants", authz.TenantCreate, s.handleCreateTenant)
	s.Route(http.MethodGet, "/api/v1/tenants", authz.TenantRead, s.handleListTenants)
	s.Route(http.MethodGet, "/api/v1/tenants/{tenantID}", authz.TenantRead, s.handleGetTenant)
	s.Route(http.MethodPut, "/api/v1/tenants/{tenantID}/settings", authz.TenantUpdate, s.handleUpdateSettings)
	s.Route(http.MethodPost, "/api/v1/tenants/{tenantID}/suspend", authz.TenantSuspend, s.handleSuspendTenant)
	s.Route(http.MethodPost, "/api/v1/tenants/{tenantID}/reinstate", authz.TenantSuspend, s.handleReinstateTenant)

	// --- Principals and roles ----------------------------------------------
	s.Route(http.MethodGet, "/api/v1/tenants/{tenantID}/principals",
		authz.PrincipalRead, s.handleListPrincipals)
	s.Route(http.MethodPost, "/api/v1/tenants/{tenantID}/principals/{principalID}/roles",
		authz.RoleAssign, s.handleAssignRole)

	// --- Projects -----------------------------------------------------------
	s.Route(http.MethodPost, "/api/v1/tenants/{tenantID}/projects",
		authz.ProjectCreate, s.handleCreateProject)
	s.Route(http.MethodGet, "/api/v1/tenants/{tenantID}/projects",
		authz.ProjectRead, s.handleListProjects)
	s.Route(http.MethodGet, "/api/v1/tenants/{tenantID}/projects/{projectID}",
		authz.ProjectRead, s.handleGetProject)
	s.Route(http.MethodPost, "/api/v1/tenants/{tenantID}/projects/{projectID}/archive",
		authz.ProjectArchive, s.handleArchiveProject)

	// --- Artifacts ----------------------------------------------------------
	const artifactBase = "/api/v1/tenants/{tenantID}/projects/{projectID}/artifacts"
	s.Route(http.MethodPost, artifactBase, authz.ArtifactCreate, s.handleCreateArtifact)
	s.Route(http.MethodGet, artifactBase, authz.ArtifactRead, s.handleListArtifacts)
	s.Route(http.MethodGet, artifactBase+"/{artifactID}", authz.ArtifactRead, s.handleGetArtifact)
	s.Route(http.MethodGet, artifactBase+"/{artifactID}/versions/{version}",
		authz.ArtifactRead, s.handleGetVersion)
	s.Route(http.MethodPut, artifactBase+"/{artifactID}/versions/{version}",
		authz.ArtifactEdit, s.handleUpdateDraft)
	s.Route(http.MethodPost, artifactBase+"/{artifactID}/versions/{version}/submit",
		authz.ArtifactSubmit, s.handleSubmit)
	s.Route(http.MethodPost, artifactBase+"/{artifactID}/versions/{version}/request-changes",
		authz.ArtifactReview, s.handleRequestChanges)
	s.Route(http.MethodPost, artifactBase+"/{artifactID}/versions/{version}/approve",
		authz.ArtifactApprove, s.handleApprove)
	s.Route(http.MethodPost, artifactBase+"/{artifactID}/versions/{version}/freeze",
		authz.ArtifactFreeze, s.handleFreeze)
	s.Route(http.MethodPost, artifactBase+"/{artifactID}/revise",
		authz.ArtifactEdit, s.handleRevise)
	s.Route(http.MethodGet, artifactBase+"/{artifactID}/versions/{version}/evidence",
		authz.ArtifactRead, s.handleEvidence)

	// --- Trace links and traceability queries -------------------------------
	const graphBase = "/api/v1/tenants/{tenantID}/projects/{projectID}"
	s.Route(http.MethodPost, graphBase+"/links", authz.LinkCreate, s.handleCreateLink)
	s.Route(http.MethodGet, graphBase+"/links", authz.LinkRead, s.handleListLinks)
	s.Route(http.MethodPost, graphBase+"/links/{linkID}/accept", authz.LinkAccept, s.handleAcceptLink)
	s.Route(http.MethodPost, graphBase+"/links/{linkID}/reject", authz.LinkReject, s.handleRejectLink)
	s.Route(http.MethodGet, graphBase+"/trace/upstream", authz.ArtifactRead, s.handleUpstream)
	s.Route(http.MethodGet, graphBase+"/trace/downstream", authz.ArtifactRead, s.handleDownstream)
	s.Route(http.MethodGet, graphBase+"/trace/impact", authz.ArtifactRead, s.handleImpact)

	// --- Audit --------------------------------------------------------------
	s.Route(http.MethodGet, "/api/v1/tenants/{tenantID}/audit", authz.AuditRead, s.handleListAudit)
	s.Route(http.MethodGet, "/api/v1/tenants/{tenantID}/audit/{sequence}",
		authz.AuditRead, s.handleGetAudit)
	s.Route(http.MethodPost, "/api/v1/tenants/{tenantID}/audit/verify",
		authz.AuditRead, s.handleVerifyAudit)
	s.Route(http.MethodPost, "/api/v1/tenants/{tenantID}/audit/anchor",
		authz.AuditExport, s.handleAnchorAudit)
}
