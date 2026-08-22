package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/authn"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/httpx"
	"github.com/specforge/specforge/internal/platform/idempotency"
	"github.com/specforge/specforge/internal/platform/log"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/ratelimit"
	"github.com/specforge/specforge/internal/platform/types"
)

// publicPrefixes are the paths that skip authentication. Kept as an explicit,
// short list so that widening it is a visible change in review.
var publicPrefixes = []string{
	"/healthz", "/readyz", "/metrics",
	"/api/v1/version", "/api/v1/openapi.json",
	"/api/v1/auth/login", "/api/v1/auth/callback",
}

func isPublic(path string) bool {
	for _, p := range publicPrefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// authenticate establishes the principal from a bearer token or API key.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublic(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()

		if key := r.Header.Get("X-Api-Key"); key != "" {
			principal, err := s.identity.AuthenticateAPIKey(ctx, key)
			if err != nil {
				httpx.WriteProblem(w, r, err, s.logger)
				return
			}
			s.continueWithPrincipal(w, r, next, principal)
			return
		}

		raw := bearerToken(r)
		if raw == "" {
			httpx.WriteProblem(w, r, errors.Unauthorized("server.authenticate",
				"auth.credentials_required",
				"Authentication is required."), s.logger)
			return
		}

		claims, err := authn.Verify(raw, s.keys, authn.VerifyOptions{
			Issuer:    s.cfg.Auth.Issuer,
			Audience:  s.cfg.Auth.Audience,
			ClockSkew: s.cfg.Auth.ClockSkew,
		})
		if err != nil {
			httpx.WriteProblem(w, r, err, s.logger)
			return
		}

		principal, err := s.identity.ResolveFromClaims(ctx, claims,
			s.cfg.Auth.TenantClaim, s.cfg.Auth.RolesClaim)
		if err != nil {
			httpx.WriteProblem(w, r, err, s.logger)
			return
		}
		s.continueWithPrincipal(w, r, next, principal)
	})
}

func (s *Server) continueWithPrincipal(w http.ResponseWriter, r *http.Request,
	next http.Handler, principal authz.Principal) {

	ctx := authz.WithPrincipal(r.Context(), principal)
	ctx = log.WithFields(ctx, log.Fields{
		PrincipalID: principal.ID.String(),
		TenantID:    principal.TenantID.String(),
	})
	if span, ok := obs.SpanFrom(ctx); ok {
		span.SetAttr("principal.id", principal.ID.String())
		span.SetAttr("principal.kind", string(principal.Kind))
		span.SetAttr("tenant.id", principal.TenantID.String())
	}
	next.ServeHTTP(w, r.WithContext(ctx))
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// resolveTenant establishes the tenant scope.
//
// The tenant comes from the token, never from the path alone. When a path
// carries a tenant identifier it must agree with the token, and a mismatch is
// refused and audited as a tenant mismatch rather than as a missing permission —
// the two are very different signals.
func (s *Server) resolveTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublic(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		principal, ok := authz.PrincipalFrom(r.Context())
		if !ok {
			httpx.WriteProblem(w, r, errors.Unauthorized("server.resolveTenant",
				"auth.credentials_required", "Authentication is required."), s.logger)
			return
		}

		tc := db.TenantContext{
			TenantID:    principal.TenantID,
			PrincipalID: principal.ID,
			BreakGlass:  principal.BreakGlass,
		}

		if pathTenant := r.PathValue("tenantID"); pathTenant != "" {
			if pathTenant != principal.TenantID.String() {
				err := errors.Forbidden("server.resolveTenant", "authz.tenant_mismatch",
					"The requested tenant does not match your credentials.")
				obs.Counter("sf_security_events_total", "Security events",
					obs.Labels{"event": "tenant_mismatch"})
				s.logger.WarnContext(r.Context(), "tenant mismatch refused",
					"principal_tenant", principal.TenantID, "path_tenant", pathTenant,
					"path", r.URL.Path)
				httpx.WriteProblem(w, r, err, s.logger)
				return
			}
		}
		if pathProject := r.PathValue("projectID"); pathProject != "" {
			pid, err := types.ParseProjectID(pathProject)
			if err != nil {
				httpx.WriteProblem(w, r, errors.Invalid("server.resolveTenant",
					"request.invalid_project_id",
					"The project identifier is not valid."), s.logger)
				return
			}
			tc.ProjectID = &pid
		}

		ctx := db.WithTenant(r.Context(), tc)
		if tc.ProjectID != nil {
			ctx = log.WithFields(ctx, log.Fields{ProjectID: tc.ProjectID.String()})
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// rateLimit applies per-principal and per-tenant limits.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	cfg := ratelimit.Config{
		PerPrincipal: ratelimit.Limit{
			Requests: s.cfg.Limits.RPSPerPrincipal, Window: time.Second,
			Burst: s.cfg.Limits.RPSPerPrincipal * s.cfg.Limits.BurstMultiplier,
		},
		PerTenant: ratelimit.Limit{
			Requests: s.cfg.Limits.RPSPerTenant, Window: time.Second,
			Burst: s.cfg.Limits.RPSPerTenant * s.cfg.Limits.BurstMultiplier,
		},
	}

	resolve := func(r *http.Request) (types.TenantID, string, bool) {
		p, ok := authz.PrincipalFrom(r.Context())
		if !ok {
			return "", "", false
		}
		return p.TenantID, p.ID.String(), true
	}

	onReject := func(w http.ResponseWriter, r *http.Request, err error) {
		httpx.WriteProblem(w, r, err, s.logger)
	}

	return s.limiter.Middleware(cfg, resolve, onReject)(next)
}

// principalOf extracts the caller, or writes a 401.
func (s *Server) principalOf(w http.ResponseWriter, r *http.Request) (authz.Principal, bool) {
	p, ok := authz.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, errors.Unauthorized("server", "auth.credentials_required",
			"Authentication is required."), s.logger)
		return authz.Principal{}, false
	}
	return p, true
}

// fail writes an error response.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	httpx.WriteProblem(w, r, err, s.logger)
}

// ok writes a JSON success response.
func (s *Server) ok(w http.ResponseWriter, r *http.Request, status int, body any) {
	if err := httpx.WriteJSON(w, status, body); err != nil {
		s.logger.ErrorContext(r.Context(), "writing response failed", "error", err)
	}
}

// idempotent runs a mutating handler under an idempotency key when one is
// supplied, replaying the stored response for a repeat of the same request.
func (s *Server) idempotent(w http.ResponseWriter, r *http.Request, body []byte,
	fn func() (int, any, error)) {

	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		status, resp, err := fn()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.ok(w, r, status, resp)
		return
	}

	ctx := r.Context()
	reqHash := idempotency.HashRequest(r.Method, r.URL.Path, body)

	rec, replay, err := s.idempotency.Begin(ctx, key, reqHash)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if replay {
		w.Header().Set("Idempotency-Replayed", "true")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		status := rec.HTTPStatus
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(rec.Body)
		return
	}

	status, resp, err := fn()
	if err != nil {
		// Release the key so the caller can correct and retry immediately rather
		// than waiting out the in-progress window.
		_ = s.idempotency.Abandon(ctx, key)
		s.fail(w, r, err)
		return
	}

	encoded, encErr := jsonBytes(resp)
	if encErr == nil {
		_ = s.idempotency.Complete(ctx, key, status, encoded)
	}
	s.ok(w, r, status, resp)
}

func jsonBytes(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return jsonMarshal(v)
}

// readBody reads and restores the request body so it can be both hashed for
// idempotency and decoded by the handler.
func readBody(r *http.Request, max int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	limited := http.MaxBytesReader(nil, r.Body, max)
	buf, err := readAll(limited)
	if err != nil {
		return nil, err
	}
	r.Body = newBodyReader(buf)
	return buf, nil
}
