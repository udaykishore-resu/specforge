package server

import (
	"context"

	artifactapp "github.com/specforge/specforge/internal/artifactgraph/app"
	"github.com/specforge/specforge/internal/platform/db"
	"github.com/specforge/specforge/internal/platform/types"
	tenancyapp "github.com/specforge/specforge/internal/tenancy/app"
)

// projectReader adapts the tenancy repository to the narrow port the artifact
// graph needs.
//
// The graph module never imports the tenancy module's domain or app packages;
// it depends only on this two-method interface. That keeps the modules
// separable and is what the architecture lint enforces.
type projectReader struct {
	repo tenancyapp.ProjectRepository
}

var _ artifactapp.ProjectReader = (*projectReader)(nil)

func newProjectReader(repo tenancyapp.ProjectRepository) *projectReader {
	return &projectReader{repo: repo}
}

func (p *projectReader) ProjectKey(ctx context.Context, tenantID types.TenantID,
	projectID types.ProjectID) (string, error) {

	project, err := p.repo.GetByID(ctx, tenantID, projectID)
	if err != nil {
		return "", err
	}
	return project.Key, nil
}

func (p *projectReader) BumpGraphVersion(ctx context.Context, tx db.Tx,
	tenantID types.TenantID, projectID types.ProjectID) (int64, error) {

	return p.repo.BumpGraphVersion(ctx, tx, tenantID, projectID)
}
