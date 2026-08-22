// Package migrate applies forward-only SQL migrations.
//
// Two properties matter for a platform that several replicas start
// simultaneously:
//
//   - An advisory lock serialises runners, so concurrent pods cannot race a DDL
//     statement against each other.
//   - Each file's checksum is recorded. A migration whose content changed after
//     it was applied is a hard error, because it means the schema in front of
//     you is not the schema the file describes.
//
// There are no down migrations. Recovery is restore-and-replay, which is the
// only approach that actually works once a migration has dropped data.
package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// advisoryLockID is an arbitrary constant that identifies the migration lock.
const advisoryLockID int64 = 0x5350_4543 // "SPEC"

// Migration is one SQL file.
type Migration struct {
	Version  string
	Name     string
	SQL      string
	Checksum string
}

// Status describes an applied migration.
type Status struct {
	Version    string
	Checksum   string
	AppliedAt  time.Time
	AppliedBy  string
	DurationMS int
}

// Runner applies migrations.
type Runner struct {
	db     *sql.DB
	logger *slog.Logger
}

// New builds a runner.
func New(db *sql.DB, logger *slog.Logger) *Runner {
	return &Runner{db: db, logger: logger}
}

// Load reads migrations from a directory, sorted by filename.
func Load(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("migrate: reading %s: %w", dir, err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("migrate: reading %s: %w", e.Name(), err)
		}
		out = append(out, newMigration(e.Name(), string(body)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// LoadFS reads migrations from an embedded filesystem, so a binary can carry
// its own schema and a deployment cannot drift from the image.
func LoadFS(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("migrate: reading %s: %w", dir, err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := fs.ReadFile(fsys, filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("migrate: reading %s: %w", e.Name(), err)
		}
		out = append(out, newMigration(e.Name(), string(body)))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func newMigration(filename, body string) Migration {
	version, name, _ := strings.Cut(strings.TrimSuffix(filename, ".sql"), "_")
	sum := sha256.Sum256([]byte(body))
	return Migration{
		Version:  version,
		Name:     strings.ReplaceAll(name, "_", " "),
		SQL:      body,
		Checksum: hex.EncodeToString(sum[:]),
	}
}

// Up applies every pending migration.
func (r *Runner) Up(ctx context.Context, migrations []Migration) (applied []string, err error) {
	if err := r.ensureTable(ctx); err != nil {
		return nil, err
	}

	unlock, err := r.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()

	existing, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}
	byVersion := make(map[string]Status, len(existing))
	for _, s := range existing {
		byVersion[s.Version] = s
	}

	for _, m := range migrations {
		if prev, done := byVersion[m.Version]; done {
			if prev.Checksum != m.Checksum {
				return applied, fmt.Errorf(
					"migrate: migration %s was already applied with a different checksum "+
						"(recorded %s, file %s); the database does not match this file",
					m.Version, prev.Checksum[:12], m.Checksum[:12])
			}
			continue
		}

		start := time.Now()
		r.logger.InfoContext(ctx, "applying migration", "version", m.Version, "name", m.Name)

		// Each migration file manages its own transaction boundaries, because
		// some statements (CREATE INDEX CONCURRENTLY) cannot run inside one.
		if _, execErr := r.db.ExecContext(ctx, m.SQL); execErr != nil {
			return applied, fmt.Errorf("migrate: applying %s (%s): %w", m.Version, m.Name, execErr)
		}

		elapsed := time.Since(start)
		if _, recErr := r.db.ExecContext(ctx, `
			INSERT INTO schema_migrations (version, checksum, duration_ms)
			VALUES ($1, $2, $3)`, m.Version, m.Checksum, int64(elapsed.Milliseconds())); recErr != nil {
			return applied, fmt.Errorf("migrate: recording %s: %w", m.Version, recErr)
		}

		applied = append(applied, m.Version)
		r.logger.InfoContext(ctx, "migration applied",
			"version", m.Version, "duration_ms", elapsed.Milliseconds())
	}
	return applied, nil
}

// Applied lists the migrations recorded in the database.
func (r *Runner) Applied(ctx context.Context) ([]Status, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT version, checksum, applied_at, applied_by, duration_ms
		  FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, fmt.Errorf("migrate: reading applied migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Status
	for rows.Next() {
		var s Status
		var dur int64
		if err := rows.Scan(&s.Version, &s.Checksum, &s.AppliedAt, &s.AppliedBy, &dur); err != nil {
			return nil, fmt.Errorf("migrate: scanning migration row: %w", err)
		}
		s.DurationMS = int(dur)
		out = append(out, s)
	}
	return out, rows.Err()
}

// Pending returns the migrations not yet applied.
func (r *Runner) Pending(ctx context.Context, migrations []Migration) ([]Migration, error) {
	if err := r.ensureTable(ctx); err != nil {
		return nil, err
	}
	applied, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}
	done := make(map[string]bool, len(applied))
	for _, s := range applied {
		done[s.Version] = true
	}
	var out []Migration
	for _, m := range migrations {
		if !done[m.Version] {
			out = append(out, m)
		}
	}
	return out, nil
}

// Verify reports any recorded migration whose file has since changed.
func (r *Runner) Verify(ctx context.Context, migrations []Migration) error {
	applied, err := r.Applied(ctx)
	if err != nil {
		return err
	}
	byVersion := make(map[string]string, len(migrations))
	for _, m := range migrations {
		byVersion[m.Version] = m.Checksum
	}
	var problems []string
	for _, s := range applied {
		want, ok := byVersion[s.Version]
		if !ok {
			problems = append(problems,
				fmt.Sprintf("migration %s is recorded in the database but has no file", s.Version))
			continue
		}
		if want != s.Checksum {
			problems = append(problems,
				fmt.Sprintf("migration %s has been edited since it was applied", s.Version))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("migrate: schema verification failed:\n  - %s",
			strings.Join(problems, "\n  - "))
	}
	return nil
}

func (r *Runner) ensureTable(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
		  version     text PRIMARY KEY,
		  checksum    text NOT NULL,
		  applied_at  timestamptz NOT NULL DEFAULT now(),
		  applied_by  text NOT NULL DEFAULT current_user,
		  duration_ms integer NOT NULL DEFAULT 0
		)`)
	if err != nil {
		return fmt.Errorf("migrate: creating schema_migrations: %w", err)
	}
	return nil
}

// lock takes the session advisory lock, waiting for any other runner.
func (r *Runner) lock(ctx context.Context) (func(), error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate: acquiring connection: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockID); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("migrate: acquiring advisory lock: %w", err)
	}
	return func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, advisoryLockID); err != nil {
			r.logger.Warn("releasing migration advisory lock failed", "error", err)
		}
		_ = conn.Close()
	}, nil
}
