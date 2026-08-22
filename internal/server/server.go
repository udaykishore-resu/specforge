// Package server wires the modules into a running HTTP service.
//
// Two things live here that are worth calling out:
//
//   - The middleware order in routes() is fixed and asserted by a test. Getting
//     it wrong is a security bug, not a style question: recovery must be
//     outermost so a panic still yields a response, and authorization must run
//     after tenant resolution so it has a tenant to compare against.
//   - Every route is registered through Route, which requires a permission to be
//     declared. A handler with no permission cannot be registered, so an
//     unprotected endpoint cannot ship by omission.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	artifactapp "github.com/specforge/specforge/internal/artifactgraph/app"
	artifactinfra "github.com/specforge/specforge/internal/artifactgraph/infra"
	auditapp "github.com/specforge/specforge/internal/audit/app"
	auditinfra "github.com/specforge/specforge/internal/audit/infra"
	identityapp "github.com/specforge/specforge/internal/identity/app"
	identityinfra "github.com/specforge/specforge/internal/identity/infra"
	"github.com/specforge/specforge/internal/platform/authn"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/cache"
	"github.com/specforge/specforge/internal/platform/config"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/httpx"
	"github.com/specforge/specforge/internal/platform/idempotency"
	"github.com/specforge/specforge/internal/platform/objstore"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/outbox"
	"github.com/specforge/specforge/internal/platform/ratelimit"
	tenancyapp "github.com/specforge/specforge/internal/tenancy/app"
	tenancyinfra "github.com/specforge/specforge/internal/tenancy/infra"
)

// Dependencies are the wired collaborators a Server needs.
type Dependencies struct {
	Config    config.Config
	DB        *db.DB
	Cache     cache.Cache
	Content   objstore.Store
	Evidence  objstore.Store
	Publisher outbox.Publisher
	Logger    *slog.Logger
	Tracer    *obs.Tracer
	// KeySource verifies bearer tokens. In development this is the local OIDC
	// provider's key set; in production it is the enterprise issuer's JWKS.
	KeySource authn.KeySource
	Issuer    string
	Audience  string
}

// Server is the SpecForge control plane.
type Server struct {
	cfg    config.Config
	logger *slog.Logger
	tracer *obs.Tracer

	db        *db.DB
	cache     cache.Cache
	publisher outbox.Publisher

	authz       *authz.Evaluator
	keys        authn.KeySource
	idempotency *idempotency.Store
	limiter     *ratelimit.Limiter

	tenancy   *tenancyapp.Service
	identity  *identityapp.Service
	artifacts *artifactapp.Service
	audit     *auditapp.Service

	relay *outbox.Relay

	mux    *http.ServeMux
	routes []routeInfo
	http   *http.Server

	readyMu sync.RWMutex
	ready   bool
}

// routeInfo records a registered route and the permission it demands.
// RouteSpec describes one registered endpoint.
//
// It is exported so the OpenAPI contract test can compare the published
// document against the router itself. Documentation that is checked against the
// code cannot drift from it, and drift is the failure mode that makes an API
// specification worse than none.
type RouteSpec struct {
	Method     string
	Pattern    string
	Permission string
	Public     bool
}

// routeInfo is retained as the internal name for RouteSpec.
type routeInfo = RouteSpec

// RouteTable builds the route table without any dependencies.
//
// Registration only records handler values; it never calls them, so a Server
// with nothing but a mux is enough to enumerate the API surface. That is what
// lets `make lint-routes` and the contract test run without a database.
func RouteTable() []RouteSpec {
	s := &Server{mux: http.NewServeMux()}
	s.registerRoutes()
	return s.Routes()
}

// New wires the modules and builds the router.
func New(deps Dependencies) (*Server, error) {
	if deps.Logger == nil {
		return nil, errors.New("server: a logger is required")
	}
	if deps.DB == nil {
		return nil, errors.New("server: a database is required")
	}

	policy := authz.Policy{
		FourEyes:               deps.Config.Governance.FourEyes,
		ArchitectCanApprovePRD: false,
		StepUpMaxAge:           deps.Config.Governance.StepUpMaxAge,
		ProdDeployFourEyes:     true,
		PolicySetVersion:       "builtin@v1",
	}
	evaluator := authz.NewEvaluator(policy)

	auditRepo := auditinfra.NewPostgres(deps.DB)
	auditService := auditapp.NewService(deps.DB, auditRepo, deps.Evidence,
		deps.Config.ObjStore.EvidenceBucket)

	outboxStore := outbox.NewStore()

	tenantRepo := tenancyinfra.NewTenantRepo(deps.DB)
	projectRepo := tenancyinfra.NewProjectRepo(deps.DB)
	tenancyService := tenancyapp.NewService(deps.DB, tenantRepo, projectRepo,
		auditService, outboxStore, evaluator, deps.Logger)

	identityRepo := identityinfra.NewPostgres(deps.DB)
	identityService := identityapp.NewService(deps.DB, identityRepo, auditService,
		outboxStore, evaluator, deps.Cache, deps.Config.Cache.TTL, deps.Logger)

	graphRepo := artifactinfra.NewPostgres(deps.DB)
	artifactService := artifactapp.NewService(deps.DB, graphRepo, auditService,
		outboxStore, evaluator, deps.Content, deps.Evidence,
		artifactapp.Buckets{
			Content:  deps.Config.ObjStore.ContentBucket,
			Evidence: deps.Config.ObjStore.EvidenceBucket,
		},
		newProjectReader(projectRepo), newBaselineGates(graphRepo),
		deps.Config.Limits.MaxGraphDepth, deps.Logger)

	s := &Server{
		cfg: deps.Config, logger: deps.Logger, tracer: deps.Tracer,
		db: deps.DB, cache: deps.Cache, publisher: deps.Publisher,
		authz: evaluator, keys: deps.KeySource,
		idempotency: idempotency.NewStore(deps.DB),
		limiter:     ratelimit.New(deps.Cache),
		tenancy:     tenancyService,
		identity:    identityService,
		artifacts:   artifactService,
		audit:       auditService,
		mux:         http.NewServeMux(),
	}

	if deps.Publisher != nil {
		s.relay = outbox.NewRelay(deps.DB, deps.Publisher, outbox.RelayConfig{
			BatchSize: deps.Config.Events.RelayBatch,
			Interval:  deps.Config.Events.RelayInterval,
		}, deps.Logger)
	}

	s.registerRoutes()
	return s, nil
}

// Handler returns the fully wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	// Order is deliberate; see the package comment and TestMiddlewareOrder.
	chain := httpx.Chain(
		httpx.Recoverer(s.logger), // outermost: a panic must still respond
		httpx.RequestID(),         // correlation before anything logs
		httpx.Tracing(s.tracer),   // span covers the rest of the chain
		httpx.Logging(s.logger),   // one line per request, with correlation
		httpx.SecurityHeaders(s.cfg.Env.IsProduction()),
		httpx.CORS(httpx.CORSOptions{AllowedOrigins: s.cfg.HTTP.AllowedOrigins}),
		httpx.BodyLimit(s.cfg.HTTP.MaxBodyBytes),
		httpx.Timeout(s.cfg.HTTP.HandlerTimeout),
		s.authenticate,  // establishes the principal
		s.resolveTenant, // establishes the tenant, from the token not the path
		s.rateLimit,     // needs the principal and tenant to key on
	)
	return chain(s.mux)
}

// Routes returns the registered routes, for the route lint and documentation.
func (s *Server) Routes() []routeInfo {
	out := append([]routeInfo(nil), s.routes...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Pattern != out[j].Pattern {
			return out[i].Pattern < out[j].Pattern
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// Route registers a handler that requires a permission.
//
// Registering a route is the only way to add an endpoint, and it demands a
// permission, so "we forgot to add authorization" is not a reachable state.
func (s *Server) Route(method, pattern string, permission authz.Permission, h http.HandlerFunc) {
	s.routes = append(s.routes, routeInfo{
		Method: method, Pattern: pattern, Permission: permission.String(),
	})
	s.mux.HandleFunc(method+" "+pattern, s.withRoutePattern(pattern, h))
}

// PublicRoute registers an unauthenticated endpoint.
//
// The set of public routes is deliberately tiny — health, readiness, metrics,
// the OpenAPI document and the login flow — and each one is listed explicitly so
// it is visible in review.
func (s *Server) PublicRoute(method, pattern string, h http.HandlerFunc) {
	s.routes = append(s.routes, routeInfo{
		Method: method, Pattern: pattern, Public: true,
	})
	s.mux.HandleFunc(method+" "+pattern, s.withRoutePattern(pattern, h))
}

func (s *Server) withRoutePattern(pattern string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := httpx.WithRoutePattern(r.Context(), pattern)
		h(w, r.WithContext(ctx))
	}
}

// Start runs the HTTP server and background workers until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	s.http = &http.Server{
		Addr:              s.cfg.HTTP.Addr,
		Handler:           s.Handler(),
		ReadTimeout:       s.cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      s.cfg.HTTP.WriteTimeout,
		IdleTimeout:       s.cfg.HTTP.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(s.logger.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	var wg sync.WaitGroup
	if s.relay != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.relay.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				s.logger.ErrorContext(ctx, "outbox relay stopped", "error", err)
			}
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.InfoContext(ctx, "http server listening",
			"addr", s.cfg.HTTP.Addr, "env", string(s.cfg.Env))
		s.setReady(true)
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		s.setReady(false)
		return err
	case <-ctx.Done():
	}

	// Graceful shutdown: stop reporting ready first so the load balancer takes
	// this instance out of rotation before connections start being refused.
	s.setReady(false)
	s.logger.Info("shutting down", "grace", s.cfg.HTTP.ShutdownTimeout.String())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.HTTP.ShutdownTimeout)
	defer cancel()

	shutdownErr := s.http.Shutdown(shutdownCtx)
	wg.Wait()

	if s.publisher != nil {
		if err := s.publisher.Close(); err != nil {
			s.logger.Warn("closing event publisher failed", "error", err)
		}
	}
	return shutdownErr
}

func (s *Server) setReady(v bool) {
	s.readyMu.Lock()
	s.ready = v
	s.readyMu.Unlock()
}

func (s *Server) isReady() bool {
	s.readyMu.RLock()
	defer s.readyMu.RUnlock()
	return s.ready
}

// Services exposes the wired services, for the seeder, the worker and tests.
func (s *Server) Services() (*tenancyapp.Service, *identityapp.Service,
	*artifactapp.Service, *auditapp.Service) {
	return s.tenancy, s.identity, s.artifacts, s.audit
}

// Relay exposes the outbox relay so the worker process can drive it.
func (s *Server) Relay() *outbox.Relay { return s.relay }

// LintRoutes reports routes that declare no permission and are not explicitly
// public. `make lint-routes` fails the build on any result.
func (s *Server) LintRoutes() []string {
	var problems []string
	for _, r := range s.Routes() {
		if r.Public {
			continue
		}
		if r.Permission == "" || strings.HasPrefix(r.Permission, "permission(") {
			problems = append(problems,
				fmt.Sprintf("%s %s declares no permission", r.Method, r.Pattern))
		}
	}
	return problems
}
