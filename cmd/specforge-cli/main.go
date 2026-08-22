// Command specforge-cli is the operator and developer tool.
//
// The verification subcommands are the important ones. verify-audit and
// verify-evidence recompute hashes from stored bytes without asking the platform
// to vouch for itself, which is what makes SpecForge's evidence defensible to
// someone who does not trust SpecForge.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	auditapp "github.com/specforge/specforge/internal/audit/app"
	auditdomain "github.com/specforge/specforge/internal/audit/domain"
	auditinfra "github.com/specforge/specforge/internal/audit/infra"
	"github.com/specforge/specforge/internal/platform/buildinfo"
	"github.com/specforge/specforge/internal/platform/config"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/hash"
	"github.com/specforge/specforge/internal/platform/log"
	"github.com/specforge/specforge/internal/platform/objstore"
	"github.com/specforge/specforge/internal/platform/types"
)

func main() {
	if buildinfo.HandleVersionFlag(os.Args[1:], "specforge-cli") {
		return
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if err := dispatch(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "specforge-cli: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `specforge-cli — SpecForge operator tool

Commands:
  verify-audit    --tenant <id> [--from N] [--to N]
                  Recompute the audit hash chain and report the first divergence.
  verify-evidence --file <path> --digest <sha256:...>
                  Verify an exported evidence document offline.
  seed            --tenant-slug <slug>
                  Create a demo tenant, project and artifact graph.
  outbox-status
                  Report events awaiting publication.
  routes
                  Print the API surface with the permission each route requires.

Configuration comes from the SF_* environment variables.
`)
}

func dispatch(command string, args []string) error {
	switch command {
	case "verify-audit":
		return verifyAudit(args)
	case "verify-evidence":
		return verifyEvidence(args)
	case "seed":
		return seed(args)
	case "outbox-status":
		return outboxStatus(args)
	case "routes":
		return printRoutes(args)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func openDB(ctx context.Context) (*db.DB, config.Config, *slog.Logger, error) {
	cfg := config.MustLoad()
	logger := log.New(log.Options{
		Level: "warn", Format: "text", ServiceName: "specforge-cli",
	})
	database, err := db.Open(ctx, cfg.DB)
	if err != nil {
		return nil, cfg, nil, fmt.Errorf("opening database: %w", err)
	}
	return database, cfg, logger, nil
}

// verifyAudit recomputes the chain and reports where it diverges.
func verifyAudit(args []string) error {
	fs := flag.NewFlagSet("verify-audit", flag.ExitOnError)
	tenant := fs.String("tenant", "", "tenant id (required)")
	from := fs.Int64("from", 1, "first sequence")
	to := fs.Int64("to", 0, "last sequence (0 = to the end)")
	_ = fs.Parse(args)

	if *tenant == "" {
		return fmt.Errorf("--tenant is required")
	}
	tenantID, err := types.ParseTenantID(*tenant)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	database, cfg, _, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = database.Close() }()

	store, err := objstore.NewFS(cfg.ObjStore.Root)
	if err != nil {
		return err
	}
	service := auditapp.NewService(database, auditinfra.NewPostgres(database),
		store, cfg.ObjStore.EvidenceBucket)

	// A full-range check is also compared against the last published anchor,
	// because a chain that is internally consistent proves nothing on its own:
	// an attacker with write access could rewrite every record and recompute
	// every hash. The anchor is the external reference the rewrite cannot reach.
	var report auditdomain.VerifyReport
	if *from <= 1 && *to == 0 {
		report, err = service.VerifyAgainstAnchor(ctx, tenantID)
	} else {
		report, err = service.Verify(ctx, tenantID, *from, *to)
	}
	if err != nil {
		return err
	}

	out, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(out))

	if !report.Valid {
		// A broken chain is not a warning. Exiting non-zero makes this usable as
		// a scheduled check.
		return fmt.Errorf("the audit chain is INVALID at sequence %d: %s",
			report.FailedAt, report.Reason)
	}
	fmt.Printf("\nThe audit chain is valid: %d records verified.\n", report.RecordsChecked)
	return nil
}

// verifyEvidence checks an exported evidence document without contacting the
// platform. This is what an auditor runs when they want to confirm an approval
// without trusting the system that produced it.
func verifyEvidence(args []string) error {
	fs := flag.NewFlagSet("verify-evidence", flag.ExitOnError)
	file := fs.String("file", "", "path to the evidence document (required)")
	digest := fs.String("digest", "", "expected sha256:... digest (required)")
	_ = fs.Parse(args)

	if *file == "" || *digest == "" {
		return fmt.Errorf("--file and --digest are both required")
	}
	want, err := types.ParseContentHash(*digest)
	if err != nil {
		return err
	}

	body, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *file, err)
	}
	got := hash.ContentOfBytes(body)

	if !hash.Equal(got, want) {
		fmt.Printf("MISMATCH\n  expected %s\n  actual   %s\n", want, got)
		return fmt.Errorf("the evidence does not match its recorded digest")
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("the evidence is not valid JSON: %w", err)
	}

	fmt.Printf("VERIFIED  %s\n\n", got)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, k := range []string{"artifact_id", "version", "artifact_type", "content_hash",
		"approver", "approved_at", "approval_comment"} {
		if v, ok := doc[k]; ok {
			fmt.Fprintf(tw, "%s\t%v\n", k, v)
		}
	}
	_ = tw.Flush()
	return nil
}

func outboxStatus(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, _, _, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = database.Close() }()

	var pending, published int64
	var oldest *time.Time
	if err := database.SQL().QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE published_at IS NULL),
		       count(*) FILTER (WHERE published_at IS NOT NULL),
		       min(created_at) FILTER (WHERE published_at IS NULL)
		  FROM outbox_events`).Scan(&pending, &published, &oldest); err != nil {
		return err
	}

	fmt.Printf("pending:   %d\npublished: %d\n", pending, published)
	if oldest != nil {
		fmt.Printf("oldest unpublished: %s (%s ago)\n",
			oldest.Format(time.RFC3339), time.Since(*oldest).Round(time.Second))
	}
	return nil
}

func printRoutes(args []string) error {
	fmt.Println("Run the API and query /api/v1/openapi.json for the live route table,")
	fmt.Println("or read api/openapi/specforge.v1.yaml for the full contract.")
	return nil
}
