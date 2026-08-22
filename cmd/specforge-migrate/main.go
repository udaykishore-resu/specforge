// Command specforge-migrate applies database migrations.
//
// Several replicas may start at once, so the runner takes a PostgreSQL advisory
// lock: one applies, the others wait and then find nothing to do. Checksums are
// verified on every run, so a migration file edited after it was applied is a
// hard failure rather than a silent divergence.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/specforge/specforge/internal/platform/buildinfo"
	"github.com/specforge/specforge/internal/platform/config"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/db/migrate"
	"github.com/specforge/specforge/internal/platform/log"
)

func main() {
	if buildinfo.HandleVersionFlag(os.Args[1:], "specforge-migrate") {
		return
	}

	var (
		command = flag.String("cmd", "up", "up | status | verify")
		dir     = flag.String("dir", "", "migrations directory (defaults to configuration)")
		timeout = flag.Duration("timeout", 5*time.Minute, "overall timeout")
	)
	flag.Parse()

	// A positional subcommand wins over the flag, because that is how everything
	// actually calls this: `specforge-migrate up` in the Makefile, in the Helm
	// pre-upgrade hook and in CI. Ignoring the argument and silently falling back
	// to the default would mean `specforge-migrate status` quietly applied
	// migrations instead of reporting on them.
	selected := *command
	if arg := flag.Arg(0); arg != "" {
		selected = arg
	}
	switch selected {
	case "up", "status", "verify":
	default:
		fmt.Fprintf(os.Stderr, "specforge-migrate: unknown command %q (expected up, status or verify)\n", selected)
		os.Exit(2)
	}

	if err := run(selected, *dir, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "specforge-migrate: %v\n", err)
		os.Exit(1)
	}
}

func run(command, dir string, timeout time.Duration) error {
	cfg := config.MustLoad()
	if dir == "" {
		dir = cfg.DB.MigrationsDir
	}

	logger := log.New(log.Options{
		Level: cfg.Obs.LogLevel, Format: cfg.Obs.LogFormat,
		ServiceName: "specforge-migrate", Version: cfg.Version, Env: string(cfg.Env),
	})
	slog.SetDefault(logger)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	database, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer func() { _ = database.Close() }()

	migrations, err := migrate.Load(dir)
	if err != nil {
		return err
	}
	if len(migrations) == 0 {
		return fmt.Errorf("no migrations found in %s", dir)
	}

	runner := migrate.New(database.SQL(), logger)

	switch command {
	case "up":
		applied, err := runner.Up(ctx, migrations)
		if err != nil {
			return err
		}
		if len(applied) == 0 {
			logger.Info("schema is up to date", "migrations", len(migrations))
			return nil
		}
		logger.Info("migrations applied", "count", len(applied), "versions", applied)
		return nil

	case "status":
		pending, err := runner.Pending(ctx, migrations)
		if err != nil {
			return err
		}
		applied, err := runner.Applied(ctx)
		if err != nil {
			return err
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "VERSION\tSTATUS\tAPPLIED AT\tDURATION")
		appliedSet := map[string]bool{}
		for _, s := range applied {
			appliedSet[s.Version] = true
			fmt.Fprintf(tw, "%s\tapplied\t%s\t%dms\n",
				s.Version, s.AppliedAt.Format(time.RFC3339), s.DurationMS)
		}
		for _, m := range pending {
			fmt.Fprintf(tw, "%s\tpending\t-\t-\n", m.Version)
		}
		_ = tw.Flush()
		fmt.Printf("\n%d applied, %d pending\n", len(applied), len(pending))
		return nil

	case "verify":
		if err := runner.Verify(ctx, migrations); err != nil {
			return err
		}
		logger.Info("schema verified", "migrations", len(migrations))
		return nil

	default:
		return fmt.Errorf("unknown command %q; expected up, status or verify", command)
	}
}
