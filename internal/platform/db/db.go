// Package db wraps database/sql with the tenant isolation contract.
//
// The central rule: a tenant-scoped query cannot execute without a tenant
// context. Tx and Conn set app.tenant_id with SET LOCAL, which the row-level
// security policies read. SET LOCAL is transaction-scoped, so a pooled
// connection can never carry one tenant's context into another tenant's work.
//
// Repositories take a db.Tx or db.Conn rather than *sql.DB, so it is not
// possible to issue an unscoped query by forgetting a WHERE clause: the policy
// applies regardless.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/config"
	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/types"

	// The default driver. Production deployments may build with the `pgx` tag,
	// which registers github.com/jackc/pgx/v5/stdlib instead; nothing above this
	// package changes because every repository targets database/sql.
	"github.com/specforge/specforge/internal/platform/db/pgwire"
)

// TenantContext carries the isolation scope through a call chain.
type TenantContext struct {
	TenantID      types.TenantID
	ProjectID     *types.ProjectID
	PrincipalID   types.PrincipalID
	IsolationMode types.IsolationMode
	BreakGlass    bool
}

type tenantCtxKey struct{}

// WithTenant attaches a tenant context.
func WithTenant(ctx context.Context, tc TenantContext) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, tc)
}

// TenantFrom reads the tenant context.
func TenantFrom(ctx context.Context) (TenantContext, bool) {
	tc, ok := ctx.Value(tenantCtxKey{}).(TenantContext)
	return tc, ok
}

// MustTenant returns the tenant context or an error. Callers that reach the
// database without one have a bug; failing here is the earliest safe point.
func MustTenant(ctx context.Context) (TenantContext, error) {
	tc, ok := TenantFrom(ctx)
	if !ok || tc.TenantID.Empty() {
		return TenantContext{}, errors.Internal("db.MustTenant", "db.missing_tenant_context",
			"A tenant-scoped database operation was attempted without a tenant context.")
	}
	return tc, nil
}

// relayCtxKey marks a platform-level session permitted to read the outbox
// across tenants. It exists for exactly one consumer: the outbox relay.
type relayCtxKey struct{}

// WithRelaySession marks the context as the outbox relay's platform session.
func WithRelaySession(ctx context.Context) context.Context {
	return context.WithValue(ctx, relayCtxKey{}, true)
}

func isRelaySession(ctx context.Context) bool {
	v, _ := ctx.Value(relayCtxKey{}).(bool)
	return v
}

// Querier is the subset of database/sql shared by *sql.DB, *sql.Conn and *sql.Tx.
type Querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Tx is a transaction with tenant scope already established.
type Tx interface {
	Querier
	// Tenant returns the scope this transaction runs under.
	Tenant() TenantContext
}

type txImpl struct {
	*sql.Tx
	tc TenantContext
}

func (t *txImpl) Tenant() TenantContext { return t.tc }

// DB is the platform's database handle.
type DB struct {
	sql              *sql.DB
	statementTimeout time.Duration
}

// Open connects and verifies the pool.
func Open(ctx context.Context, cfg config.DBConfig) (*DB, error) {
	driver := cfg.Driver
	if driver == "" {
		driver = "pgwire"
	}
	sdb, err := sql.Open(driver, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("db: opening %s: %w", driver, err)
	}
	sdb.SetMaxOpenConns(cfg.MaxOpenConns)
	sdb.SetMaxIdleConns(cfg.MaxIdleConns)
	sdb.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	sdb.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := sdb.PingContext(pingCtx); err != nil {
		_ = sdb.Close()
		return nil, fmt.Errorf("db: connecting: %w", err)
	}

	return &DB{sql: sdb, statementTimeout: cfg.StatementTimeout}, nil
}

// FromSQL wraps an existing *sql.DB. Used by tests.
func FromSQL(sdb *sql.DB, statementTimeout time.Duration) *DB {
	return &DB{sql: sdb, statementTimeout: statementTimeout}
}

// SQL exposes the underlying handle for migrations and health checks only.
// Repositories must not use it: it bypasses the tenant session setup.
func (d *DB) SQL() *sql.DB { return d.sql }

// Close releases the pool.
func (d *DB) Close() error { return d.sql.Close() }

// Ping checks connectivity.
func (d *DB) Ping(ctx context.Context) error { return d.sql.PingContext(ctx) }

// Stats reports pool statistics for the metrics endpoint.
func (d *DB) Stats() sql.DBStats { return d.sql.Stats() }

// RecordPoolMetrics publishes pool gauges. Called from the metrics collector.
func (d *DB) RecordPoolMetrics() {
	s := d.sql.Stats()
	const help = "Database connection pool state"
	obs.GaugeSet("sf_db_pool_connections", help, obs.Labels{"state": "open"}, float64(s.OpenConnections))
	obs.GaugeSet("sf_db_pool_connections", help, obs.Labels{"state": "in_use"}, float64(s.InUse))
	obs.GaugeSet("sf_db_pool_connections", help, obs.Labels{"state": "idle"}, float64(s.Idle))
	obs.GaugeSet("sf_db_pool_connections", help, obs.Labels{"state": "wait_count"}, float64(s.WaitCount))
}

// TxOptions configures a transaction.
type TxOptions struct {
	ReadOnly  bool
	Isolation sql.IsolationLevel
}

// Tx runs fn inside a transaction with the tenant session established.
//
// The session variables are set with SET LOCAL so they are rolled back with the
// transaction and cannot outlive it on a pooled connection. If fn returns an
// error or panics, the transaction is rolled back.
func (d *DB) Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error {
	return d.TxWith(ctx, TxOptions{}, fn)
}

// TxWith runs fn in a transaction with explicit options.
func (d *DB) TxWith(ctx context.Context, opts TxOptions, fn func(ctx context.Context, tx Tx) error) (err error) {
	const op = "db.Tx"

	tc, tcErr := MustTenant(ctx)
	relay := isRelaySession(ctx)
	if tcErr != nil && !relay {
		return tcErr
	}

	start := time.Now()
	stx, err := d.sql.BeginTx(ctx, &sql.TxOptions{
		ReadOnly:  opts.ReadOnly,
		Isolation: opts.Isolation,
	})
	if err != nil {
		return errors.Wrap(err, op, errors.KindUnavailable, "db.begin_failed",
			"Could not start a database transaction.")
	}

	defer func() {
		if p := recover(); p != nil {
			_ = stx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = stx.Rollback()
			obs.Counter("sf_db_transactions_total", "Database transactions",
				obs.Labels{"outcome": "rollback"})
			return
		}
		if cErr := stx.Commit(); cErr != nil {
			err = errors.Wrap(cErr, op, errors.KindUnavailable, "db.commit_failed",
				"Could not commit the database transaction.")
			obs.Counter("sf_db_transactions_total", "Database transactions",
				obs.Labels{"outcome": "commit_failed"})
			return
		}
		obs.Counter("sf_db_transactions_total", "Database transactions",
			obs.Labels{"outcome": "commit"})
		obs.Observe("sf_db_transaction_duration_seconds", "Transaction duration",
			nil, time.Since(start).Seconds())
	}()

	if err = d.applySession(ctx, stx, tc, relay); err != nil {
		return err
	}

	tx := &txImpl{Tx: stx, tc: tc}
	err = fn(ctx, tx)
	return err
}

// applySession establishes the RLS session variables for this transaction.
func (d *DB) applySession(ctx context.Context, stx *sql.Tx, tc TenantContext, relay bool) error {
	const op = "db.applySession"

	timeout := d.statementTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	// SET LOCAL does not accept placeholders, so the values are validated and
	// quoted rather than bound. TenantID and PrincipalID are UUID-validated value
	// objects, and quoteLiteral is applied as a second line of defence.
	stmts := []string{
		fmt.Sprintf("SET LOCAL statement_timeout = %d", timeout.Milliseconds()),
		fmt.Sprintf("SET LOCAL idle_in_transaction_session_timeout = %d", (timeout * 2).Milliseconds()),
	}
	if !tc.TenantID.Empty() {
		stmts = append(stmts,
			"SET LOCAL app.tenant_id = "+quoteLiteral(tc.TenantID.String()))
	}
	if tc.PrincipalID != "" {
		stmts = append(stmts,
			"SET LOCAL app.principal_id = "+quoteLiteral(tc.PrincipalID.String()))
	}
	if tc.BreakGlass {
		stmts = append(stmts, "SET LOCAL app.break_glass = 'on'")
	}
	if relay {
		stmts = append(stmts, "SET LOCAL app.relay = 'on'")
	}

	for _, s := range stmts {
		if _, err := stx.ExecContext(ctx, s); err != nil {
			return errors.Wrap(err, op, errors.KindUnavailable, "db.session_setup_failed",
				"Could not establish the tenant database session.")
		}
	}
	return nil
}

// quoteLiteral escapes a value for inclusion in a SQL literal.
//
// Only ever applied to already-validated UUID value objects; it exists so that
// a future caller passing something unvalidated still cannot break out.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// ReadOnly runs fn against a tenant-scoped read transaction.
func (d *DB) ReadOnly(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error {
	return d.TxWith(ctx, TxOptions{ReadOnly: true}, fn)
}

// Health reports database health for the readiness endpoint.
func (d *DB) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var one int
	if err := d.sql.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("db: health check: %w", err)
	}
	return nil
}

// SQLState extracts the five-character SQLSTATE from a driver error, if the
// driver exposes one. Repositories branch on this rather than on error strings.
func SQLState(err error) (string, bool) {
	var pe *pgwire.Error
	if errors.As(err, &pe) {
		return pe.SQLState(), pe.SQLState() != ""
	}
	// Any driver exposing the conventional SQLState method works too, so a
	// deployment built with the pgx tag behaves identically here.
	type sqlStater interface{ SQLState() string }
	var s sqlStater
	if errors.As(err, &s) {
		return s.SQLState(), s.SQLState() != ""
	}
	return "", false
}

// ConstraintViolation reports whether err is an integrity constraint violation
// and, when the driver supplies it, which constraint failed.
//
// This is how database-enforced invariants (sealed-artifact immutability, the
// single-approved-version index, the LLM-link disposition check) surface as
// domain errors instead of opaque 500s.
func ConstraintViolation(err error) (constraint string, ok bool) {
	state, has := SQLState(err)
	if !has || !strings.HasPrefix(state, "23") { // class 23: integrity_constraint_violation
		return "", false
	}
	var pe *pgwire.Error
	if errors.As(err, &pe) {
		return pe.Constraint, true
	}
	return "", true
}

// IsUniqueViolation reports a duplicate key error (SQLSTATE 23505).
func IsUniqueViolation(err error) bool {
	state, ok := SQLState(err)
	return ok && state == "23505"
}

// IsCheckViolation reports a CHECK or trigger-raised constraint failure (23514).
func IsCheckViolation(err error) bool {
	state, ok := SQLState(err)
	return ok && state == "23514"
}

// IsForeignKeyViolation reports a referential integrity failure (23503).
func IsForeignKeyViolation(err error) bool {
	state, ok := SQLState(err)
	return ok && state == "23503"
}

// IsRLSViolation reports a row-level security policy rejection (42501).
// This should never happen in correct code; when it does it means a write tried
// to cross a tenant boundary and the database refused.
func IsRLSViolation(err error) bool {
	state, ok := SQLState(err)
	return ok && state == "42501"
}

// IsNoRows reports whether a query returned no rows.
func IsNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
