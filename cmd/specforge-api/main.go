// Command specforge-api runs the SpecForge control plane.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/specforge/specforge/internal/platform/authn"
	"github.com/specforge/specforge/internal/platform/buildinfo"
	"github.com/specforge/specforge/internal/platform/cache"
	"github.com/specforge/specforge/internal/platform/config"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/eventbus"
	"github.com/specforge/specforge/internal/platform/log"
	"github.com/specforge/specforge/internal/platform/objstore"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/outbox"
	"github.com/specforge/specforge/internal/server"
)

func main() {
	if buildinfo.HandleVersionFlag(os.Args[1:], "specforge-api") {
		return
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "specforge-api: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := config.MustLoad()

	logger := log.New(log.Options{
		Level: cfg.Obs.LogLevel, Format: cfg.Obs.LogFormat,
		ServiceName: cfg.ServiceName, Version: cfg.Version, Env: string(cfg.Env),
	})
	slog.SetDefault(logger)

	logger.Info("starting", "config", fmt.Sprintf("%+v", cfg.Redacted()))

	// SIGTERM begins graceful shutdown. Kubernetes sends it before removing the
	// pod, and the preStop hook gives the load balancer time to deregister first.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Telemetry ----------------------------------------------------------
	var exporter obs.Exporter = obs.NopExporter{}
	if cfg.Obs.OTLPEndpoint != "" {
		exporter = obs.NewBatchExporter(
			obs.NewOTLPExporter(cfg.Obs.OTLPEndpoint, cfg.ServiceName, nil),
			2048, 256, 5*time.Second)
	}
	tracer := obs.NewTracer(cfg.ServiceName, cfg.Obs.SampleRatio, exporter)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exporter.Shutdown(shutdownCtx)
	}()

	// --- Data plane ---------------------------------------------------------
	database, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = database.Close() }()

	cacheStore, err := openCache(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = cacheStore.Close() }()

	contentStore, evidenceStore, err := openObjectStores(cfg, database)
	if err != nil {
		return err
	}

	publisher, err := openPublisher(cfg, logger)
	if err != nil {
		return err
	}

	// --- Identity -----------------------------------------------------------
	keys, issuer, audience, devIdP, err := setupIdentity(ctx, &cfg, database, logger)
	if err != nil {
		return err
	}
	cfg.Auth.Issuer = issuer
	cfg.Auth.Audience = audience

	if devIdP != nil {
		go serveDevIdP(ctx, cfg, devIdP, logger)
	}

	// The metrics listener is separate from the API's own /metrics route.
	//
	// Both serve the same registry; they differ in who can reach them. The
	// route on the public listener is convenient for a developer with curl,
	// and the dedicated address is what Prometheus is pointed at and what a
	// deployment can bind somewhere only the scraper reaches. SF_METRICS_ADDR
	// was previously read and never used, so the scrape target named in
	// prometheus.yml had nothing listening on it.
	if cfg.Obs.MetricsAddr != "" {
		go func() {
			if err := obs.ServeMetrics(ctx, cfg.Obs.MetricsAddr, logger, database.RecordPoolMetrics); err != nil {
				logger.Error("metrics endpoint stopped", "error", err)
			}
		}()
	}

	// --- Server -------------------------------------------------------------
	srv, err := server.New(server.Dependencies{
		Config: cfg, DB: database, Cache: cacheStore,
		Content: contentStore, Evidence: evidenceStore,
		Publisher: publisher, Logger: logger, Tracer: tracer,
		KeySource: keys, Issuer: issuer, Audience: audience,
	})
	if err != nil {
		return fmt.Errorf("wiring server: %w", err)
	}

	if problems := srv.LintRoutes(); len(problems) > 0 {
		// A route without a declared permission is an unprotected endpoint.
		// Refusing to start is the only safe response.
		for _, p := range problems {
			logger.Error("route lint failure", "problem", p)
		}
		return fmt.Errorf("refusing to start: %d route(s) declare no permission", len(problems))
	}

	return srv.Start(ctx)
}

func openCache(ctx context.Context, cfg config.Config) (cache.Cache, error) {
	switch cfg.Cache.Provider {
	case "redis":
		c, err := cache.NewRedis(ctx, cache.RedisOptions{
			Addr: cfg.Cache.Addr, Password: cfg.Cache.Password,
			DB: cfg.Cache.DB, TLS: cfg.Cache.TLS,
		})
		if err != nil {
			return nil, fmt.Errorf("connecting to redis: %w", err)
		}
		return c, nil
	default:
		return cache.NewMemory(100_000), nil
	}
}

// openObjectStores builds the content and evidence stores.
//
// One store backs both: the bucket name separates them, so content and evidence
// never share a namespace even though they share an adapter.
func openObjectStores(cfg config.Config, database *db.DB) (content, evidence objstore.Store, err error) {
	store, err := objstore.Open(cfg.ObjStore.Provider, cfg.ObjStore.Root, database.SQL())
	if err != nil {
		return nil, nil, err
	}
	return store, store, nil
}

func openPublisher(cfg config.Config, logger *slog.Logger) (outbox.Publisher, error) {
	inproc := eventbus.NewInProcess(logger)
	switch cfg.Events.Provider {
	case "log":
		fl, err := eventbus.NewFileLog(cfg.Events.LogDir, cfg.Events.TopicPrefix, inproc)
		if err != nil {
			return nil, fmt.Errorf("opening event log: %w", err)
		}
		return fl, nil
	default:
		return inproc, nil
	}
}

// devTenantResolver answers which tenant the development accounts belong to,
// asked afresh each time a token is issued.
//
// Order: an explicit SF_DEV_TENANT_ID if that tenant actually exists, then the
// tenant named by SF_DEV_TENANT_SLUG (default "acme"). The existence check is
// the point — an id left over from a previous database is worse than no id at
// all, because it produces tokens that look correct and fail on a foreign key
// three layers down.
func devTenantResolver(database *db.DB, logger *slog.Logger) func() string {
	slug := os.Getenv("SF_DEV_TENANT_SLUG")
	if slug == "" {
		slug = "acme"
	}
	warned := false

	return func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		if configured := os.Getenv("SF_DEV_TENANT_ID"); configured != "" {
			var exists bool
			err := database.SQL().QueryRowContext(ctx,
				`SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)`, configured).Scan(&exists)
			if err == nil && exists {
				return configured
			}
			if err == nil && !warned {
				warned = true
				logger.Warn("SF_DEV_TENANT_ID names a tenant that does not exist; "+
					"falling back to a lookup by slug",
					"configured", configured, "slug", slug)
			}
		}

		var id string
		if err := database.SQL().QueryRowContext(ctx,
			`SELECT id::text FROM tenants WHERE slug = $1`, slug).Scan(&id); err != nil {
			return ""
		}
		return id
	}
}

// setupIdentity resolves the token verification key source.
//
// In development the built-in provider supplies it; in every other environment
// the enterprise issuer's JWKS does. The dev provider refuses to run in
// production, and the configuration validator refuses to start a production
// process with it enabled, so there are two independent guards.
func setupIdentity(ctx context.Context, cfg *config.Config, database *db.DB,
	logger *slog.Logger) (authn.KeySource, string, string, *authn.DevIdP, error) {

	if cfg.Auth.DevIdP {
		if cfg.Env.IsProduction() {
			return nil, "", "", nil, fmt.Errorf("the development identity provider cannot run in production")
		}
		// The issuer must be the URL a browser can actually reach, which is not
		// necessarily the address the process binds to: inside a container the
		// two differ. SF_AUTH_ISSUER overrides it for exactly that case.
		issuer := cfg.Auth.Issuer
		if issuer == "" {
			issuer = "http://127.0.0.1" + cfg.Auth.DevIdPAddr
		}
		clientID := "specforge-web"
		redirects := []string{
			cfg.HTTP.PublicBaseURL + "/api/v1/auth/callback",
			"http://localhost:3000/api/auth/callback",
		}
		if cfg.Auth.RedirectURL != "" {
			redirects = append(redirects, cfg.Auth.RedirectURL)
		}

		idp, err := authn.NewDevIdP(authn.DevIdPOptions{
			Issuer: issuer, ClientID: clientID,
			RedirectURIs:  redirects,
			Users:         authn.DefaultDevUsers(os.Getenv("SF_DEV_TENANT_ID")),
			ResolveTenant: devTenantResolver(database, logger),
			TenantClaim:   cfg.Auth.TenantClaim, RolesClaim: cfg.Auth.RolesClaim,
		})
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("starting the development identity provider: %w", err)
		}
		keys, err := idp.KeySource()
		if err != nil {
			return nil, "", "", nil, err
		}
		logger.Warn("development identity provider enabled",
			"issuer", issuer, "sign_in", issuer+"/authorize")
		return keys, issuer, clientID, idp, nil
	}

	jwksURL := cfg.Auth.JWKSURL
	if jwksURL == "" {
		provider, err := authn.NewOIDCProvider(ctx, authn.OIDCConfig{
			Issuer: cfg.Auth.Issuer, ClientID: cfg.Auth.ClientID,
			ClientSecret: cfg.Auth.ClientSecret, RedirectURL: cfg.Auth.RedirectURL,
			Audience: cfg.Auth.Audience, JWKSTTL: cfg.Auth.JWKSTTL,
		})
		if err != nil {
			return nil, "", "", nil, fmt.Errorf("configuring the identity provider: %w", err)
		}
		meta, err := provider.Metadata(ctx)
		if err != nil {
			return nil, "", "", nil, err
		}
		jwksURL = meta.JWKSURI
	}

	jwks := authn.NewJWKSCache(jwksURL, cfg.Auth.JWKSTTL)
	if err := jwks.Refresh(ctx); err != nil {
		return nil, "", "", nil, fmt.Errorf("loading issuer keys: %w", err)
	}
	return jwks, cfg.Auth.Issuer, cfg.Auth.Audience, nil, nil
}

func serveDevIdP(ctx context.Context, cfg config.Config, idp *authn.DevIdP, logger *slog.Logger) {
	srv := &http.Server{
		Addr:              cfg.Auth.DevIdPAddr,
		Handler:           idp.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("development identity provider stopped", "error", err)
	}
}
