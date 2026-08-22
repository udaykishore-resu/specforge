package pgwire_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/specforge/specforge/internal/platform/db/pgwire"
)

// testDSN returns the DSN for an integration database, or "" to skip.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SF_TEST_DSN")
	if dsn == "" {
		t.Skip("SF_TEST_DSN not set; skipping PostgreSQL integration tests")
	}
	return dsn
}

func open(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open(pgwire.DriverName, testDSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	return db
}

func TestParseDSN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		dsn     string
		want    func(*pgwire.Config) bool
		wantErr string
	}{
		{
			name: "url form",
			dsn:  "postgres://sf:secret@db.internal:6543/specforge?sslmode=verify-full&application_name=api",
			want: func(c *pgwire.Config) bool {
				return c.User == "sf" && c.Password == "secret" && c.Host == "db.internal" &&
					c.Port == 6543 && c.Database == "specforge" &&
					c.SSLMode == pgwire.SSLVerifyFull && c.ApplicationName == "api"
			},
		},
		{
			name: "keyword form",
			dsn:  "host=127.0.0.1 port=5433 user=postgres dbname=sf sslmode=disable",
			want: func(c *pgwire.Config) bool {
				return c.Host == "127.0.0.1" && c.Port == 5433 && c.User == "postgres" &&
					c.Database == "sf" && c.SSLMode == pgwire.SSLDisable
			},
		},
		{
			name: "quoted password with spaces",
			dsn:  "host=h user=u password='a b c' dbname=d sslmode=require",
			want: func(c *pgwire.Config) bool { return c.Password == "a b c" },
		},
		{
			name:    "sslmode=prefer is refused",
			dsn:     "host=h user=u sslmode=prefer",
			wantErr: "not supported",
		},
		{
			name:    "missing user",
			dsn:     "host=h dbname=d",
			wantErr: "missing a user",
		},
		{
			name:    "bad port",
			dsn:     "host=h user=u port=notanumber",
			wantErr: "invalid port",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := pgwire.ParseDSN(tc.dsn)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.want(cfg) {
				t.Fatalf("config mismatch: %+v", cfg)
			}
		})
	}
}

func TestTextArrayRoundTrip(t *testing.T) {
	t.Parallel()
	cases := [][]string{
		{},
		{"artifact:read"},
		{"artifact:read", "artifact:create"},
		{`weird,value`, `with "quotes"`, `back\slash`},
	}
	for _, in := range cases {
		out := pgwire.ParseTextArray(pgwire.TextArray(in))
		if len(in) == 0 {
			if len(out) != 0 {
				t.Fatalf("empty array round-tripped to %v", out)
			}
			continue
		}
		if len(out) != len(in) {
			t.Fatalf("length mismatch: %v -> %v", in, out)
		}
		for i := range in {
			if in[i] != out[i] {
				t.Fatalf("element %d: %q -> %q", i, in[i], out[i])
			}
		}
	}
}

func TestConnectAndQuery(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	var one int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("select 1: %v", err)
	}
	if one != 1 {
		t.Fatalf("want 1, got %d", one)
	}

	var (
		i   int64
		f   float64
		b   bool
		s   string
		ts  time.Time
		raw []byte
		nul sql.NullString
	)
	err := db.QueryRowContext(ctx, `
		SELECT $1::bigint, $2::float8, $3::boolean, $4::text,
		       $5::timestamptz, $6::jsonb, NULL::text`,
		int64(42), 3.5, true, "hello",
		time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
		`{"k":"v"}`,
	).Scan(&i, &f, &b, &s, &ts, &raw, &nul)
	if err != nil {
		t.Fatalf("typed round trip: %v", err)
	}
	if i != 42 || f != 3.5 || !b || s != "hello" {
		t.Fatalf("scalar mismatch: %d %f %t %q", i, f, b, s)
	}
	if !ts.Equal(time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("timestamp mismatch: %s", ts)
	}
	var decoded map[string]string
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded["k"] != "v" {
		t.Fatalf("jsonb mismatch: %s (%v)", raw, err)
	}
	if nul.Valid {
		t.Fatalf("expected NULL to scan as invalid")
	}
}

func TestMultiRowQuery(t *testing.T) {
	db := open(t)
	rows, err := db.QueryContext(context.Background(),
		"SELECT g, 'row-' || g FROM generate_series(1, $1) g", 100)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	n := 0
	for rows.Next() {
		var id int
		var label string
		if err := rows.Scan(&id, &label); err != nil {
			t.Fatalf("scan: %v", err)
		}
		n++
		if id != n {
			t.Fatalf("row %d out of order: %d", n, id)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if n != 100 {
		t.Fatalf("want 100 rows, got %d", n)
	}
}

func TestEarlyRowsCloseLeavesConnectionUsable(t *testing.T) {
	db := open(t)
	db.SetMaxOpenConns(1) // force reuse of the same connection
	ctx := context.Background()

	rows, err := db.QueryContext(ctx, "SELECT g FROM generate_series(1, 1000) g")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	rows.Next()
	_ = rows.Close()

	var one int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("connection unusable after early close: %v", err)
	}
}

func TestTransactionCommitAndRollback(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS pgwire_tx_test (v int)`); err != nil {
		t.Skipf("temp table unavailable (pooled connection): %v", err)
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO pgwire_tx_test VALUES ($1)`, 1); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pgwire_tx_test`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("rollback did not discard the row: %d", n)
	}
}

func TestServerErrorCarriesSQLState(t *testing.T) {
	db := open(t)
	_, err := db.ExecContext(context.Background(), `SELECT * FROM table_that_does_not_exist_xyz`)
	if err == nil {
		t.Fatal("expected an error")
	}
	pe, ok := pgwire.AsError(err)
	if !ok {
		t.Fatalf("want a *pgwire.Error, got %T: %v", err, err)
	}
	if pe.SQLState() != "42P01" { // undefined_table
		t.Fatalf("want SQLSTATE 42P01, got %q (%s)", pe.SQLState(), pe.Message)
	}
}

func TestConnectionSurvivesQueryError(t *testing.T) {
	db := open(t)
	db.SetMaxOpenConns(1)
	ctx := context.Background()

	_, _ = db.ExecContext(ctx, `SELECT 1/0`)

	var one int
	if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		t.Fatalf("connection unusable after a server error: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	db := open(t)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := db.ExecContext(ctx, "SELECT pg_sleep(10)")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("cancellation took too long: %s", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		// A server-side cancellation surfaces as SQLSTATE 57014.
		if pe, ok := pgwire.AsError(err); !ok || pe.SQLState() != "57014" {
			t.Fatalf("unexpected error: %v", err)
		}
	}
}

func TestCountPlaceholdersIgnoresLiterals(t *testing.T) {
	db := open(t)
	// A dollar sign inside a string literal must not be counted as a placeholder.
	var s string
	err := db.QueryRowContext(context.Background(),
		`SELECT 'costs $5 and $10' || $1::text`, "!").Scan(&s)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if s != "costs $5 and $10!" {
		t.Fatalf("got %q", s)
	}
}
