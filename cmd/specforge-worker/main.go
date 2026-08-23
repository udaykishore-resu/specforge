// Command specforge-worker runs the asynchronous side of the platform.
//
// Roles are selected with --roles so that a noisy workload can be split into its
// own deployment without a code change. Each role is idempotent and resumable:
// the worker may be killed at any point and the work is picked up again.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	auditapp "github.com/specforge/specforge/internal/audit/app"
	auditinfra "github.com/specforge/specforge/internal/audit/infra"
	"github.com/specforge/specforge/internal/platform/buildinfo"
	"github.com/specforge/specforge/internal/platform/config"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/eventbus"
	"github.com/specforge/specforge/internal/platform/idempotency"
	"github.com/specforge/specforge/internal/platform/log"
	"github.com/specforge/specforge/internal/platform/objstore"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/outbox"
	"github.com/specforge/specforge/internal/platform/types"
)

func main() {
	if buildinfo.HandleVersionFlag(os.Args[1:], "specforge-worker") {
		return
	}
	roles := flag.String("roles", "outbox,anchor,gc",
		"comma-separated roles: outbox, anchor, gc, integrity")
	flag.Parse()

	if err := run(strings.Split(*roles, ",")); err != nil {
		fmt.Fprintf(os.Stderr, "specforge-worker: %v\n", err)
		os.Exit(1)
	}
}

func run(roles []string) error {
	cfg := config.MustLoad()

	logger := log.New(log.Options{
		Level: cfg.Obs.LogLevel, Format: cfg.Obs.LogFormat,
		ServiceName: "specforge-worker", Version: cfg.Version, Env: string(cfg.Env),
	})
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	database, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = database.Close() }()

	store, err := objstore.Open(cfg.ObjStore.Provider, cfg.ObjStore.Root, database.SQL())
	if err != nil {
		return fmt.Errorf("opening object store: %w", err)
	}

	auditService := auditapp.NewService(database, auditinfra.NewPostgres(database),
		store, cfg.ObjStore.EvidenceBucket)

	var wg sync.WaitGroup

	// Metrics first, and on its own listener: the worker has no other HTTP
	// surface, so without this the outbox depth, the age of the oldest
	// unpublished event and the audit chain's validity are all invisible, and
	// the alerts that watch them can never fire.
	if cfg.Obs.MetricsAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := obs.ServeMetrics(ctx, cfg.Obs.MetricsAddr, logger, database.RecordPoolMetrics); err != nil {
				logger.Error("metrics endpoint stopped", "error", err)
			}
		}()
	}

	// The worker starts alongside the migration job, so on a fresh deployment
	// the schema may not exist for a few seconds. Waiting is the difference
	// between a clean startup and a burst of alarming errors about missing
	// tables that resolve themselves.
	if err := waitForSchema(ctx, database, logger); err != nil {
		return err
	}
	enabled := map[string]bool{}
	for _, r := range roles {
		enabled[strings.TrimSpace(r)] = true
	}

	if enabled["outbox"] {
		publisher := eventbus.NewInProcess(logger)
		relay := outbox.NewRelay(database, publisher, outbox.RelayConfig{
			BatchSize: cfg.Events.RelayBatch, Interval: cfg.Events.RelayInterval,
		}, logger)

		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info("outbox relay started")
			if err := relay.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("outbox relay stopped", "error", err)
			}
		}()

		// Publish the pending count so the alert in
		// docs/architecture/18-observability-architecture.md §8 has a signal.
		wg.Add(1)
		go func() {
			defer wg.Done()
			every(ctx, 30*time.Second, func(ctx context.Context) {
				n, err := relay.PendingCount(ctx)
				if err == nil {
					obs.GaugeSet("sf_outbox_pending", "Events awaiting publication", nil, float64(n))
				}
			})
		}()
	}

	if enabled["anchor"] {
		// Anchoring is what turns the audit chain from internally consistent into
		// externally verifiable, so it runs on a schedule rather than on demand.
		wg.Add(1)
		go func() {
			defer wg.Done()
			every(ctx, time.Hour, func(ctx context.Context) {
				anchorAll(ctx, database, auditService, logger)
			})
		}()
	}

	if enabled["gc"] {
		idem := idempotency.NewStore(database)
		wg.Add(1)
		go func() {
			defer wg.Done()
			every(ctx, 15*time.Minute, func(ctx context.Context) {
				if n, err := idem.GC(ctx); err != nil {
					logger.Warn("idempotency GC failed", "error", err)
				} else if n > 0 {
					logger.Info("idempotency records expired", "count", n)
				}
				expireRoleAssignments(ctx, database, logger)
			})
		}()
	}

	logger.Info("worker started", "roles", roles)
	<-ctx.Done()
	logger.Info("worker shutting down")

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		logger.Warn("worker shutdown timed out; exiting anyway")
	}
	return nil
}

// every runs fn on an interval until the context is cancelled.
// waitForSchema blocks until the migrations have been applied.
//
// It gives up after two minutes rather than waiting forever: a worker that
// never becomes useful should say so and let the orchestrator restart it, not
// sit silently in a loop that looks like health.
func waitForSchema(ctx context.Context, database *db.DB, logger *slog.Logger) error {
	const probe = `SELECT 1 FROM tenants LIMIT 1`

	deadline := time.Now().Add(2 * time.Minute)
	announced := false
	for {
		var one int
		err := database.SQL().QueryRowContext(ctx, probe).Scan(&one)
		if err == nil || err == sql.ErrNoRows {
			if announced {
				logger.Info("schema is ready")
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the schema is still not present after two minutes: %w", err)
		}
		if !announced {
			announced = true
			logger.Info("waiting for the migrations to be applied")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// every runs fn immediately and then on an interval.
//
// Immediately matters. With a ticker alone, an hourly job does nothing for its
// first hour, so a misconfiguration — an unreachable object store, a missing
// permission — surfaces an hour after the deployment that caused it, long after
// anyone is still watching. It also means a freshly seeded stack has no audit
// anchor to verify against until the hour is up, which makes the platform's
// strongest claim unavailable exactly when someone is first evaluating it.
func every(ctx context.Context, d time.Duration, fn func(context.Context)) {
	fn(ctx)
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn(ctx)
		}
	}
}

// anchorAll publishes a chain head for every active tenant.
func anchorAll(ctx context.Context, database *db.DB, audit *auditapp.Service, logger *slog.Logger) {
	rows, err := database.SQL().QueryContext(ctx,
		`SELECT id FROM tenants WHERE status = 'ACTIVE'`)
	if err != nil {
		logger.Error("listing tenants for anchoring failed", "error", err)
		return
	}
	defer func() { _ = rows.Close() }()

	var tenantIDs []types.TenantID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			logger.Error("scanning tenant failed", "error", err)
			return
		}
		tenantIDs = append(tenantIDs, types.TenantID(id))
	}

	for _, tenantID := range tenantIDs {
		anchor, err := audit.Anchor(ctx, tenantID)
		if err != nil {
			logger.Error("anchoring the audit chain failed",
				"tenant_id", tenantID, "error", err)
			continue
		}
		if anchor != nil {
			logger.Info("audit chain anchored",
				"tenant_id", tenantID, "sequence", anchor.Sequence)
		}
	}
}

// expireRoleAssignments removes grants past their expiry.
//
// Time-boxed access that quietly outlives its expiry is worse than no expiry at
// all, because it looks controlled while it is not.
func expireRoleAssignments(ctx context.Context, database *db.DB, logger *slog.Logger) {
	res, err := database.SQL().ExecContext(ctx,
		`DELETE FROM role_assignments WHERE expires_at IS NOT NULL AND expires_at < now()`)
	if err != nil {
		logger.Warn("expiring role assignments failed", "error", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		logger.Info("expired role assignments removed", "count", n)
		obs.CounterAdd("sf_role_assignments_expired_total",
			"Role assignments removed at expiry", nil, float64(n))
	}
}
