package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	tenancyinfra "github.com/specforge/specforge/internal/tenancy/infra"
)

// tenantID prints a tenant's identifier and nothing else.
//
// It exists so that scripts can wire the development identity provider to the
// seeded tenant without parsing the seeder's human-readable output. Anything
// that has to scrape a banner breaks the first time the banner changes.
func tenantID(args []string) error {
	fs := flag.NewFlagSet("tenant-id", flag.ExitOnError)
	slug := fs.String("slug", "acme", "tenant slug")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	database, _, _, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = database.Close() }()

	tenant, err := tenancyinfra.NewTenantRepo(database).GetBySlug(ctx, *slug)
	if err != nil {
		return err
	}
	if tenant == nil {
		return fmt.Errorf("no tenant with the slug %q — has `make seed` run?", *slug)
	}
	fmt.Println(tenant.ID)
	return nil
}
