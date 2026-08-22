package domain

import (
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/fsm"
	"github.com/specforge/specforge/internal/platform/types"
)

// Project lifecycle states.
const (
	ProjectActive   fsm.State = "ACTIVE"
	ProjectArchived fsm.State = "ARCHIVED"
	ProjectPurged   fsm.State = "PURGED"
)

// Project lifecycle events.
const (
	EventArchive fsm.Event = "archive"
	EventRestore fsm.Event = "restore"
	EventPurge   fsm.Event = "purge"
)

// PDLCPhase is the AI Product Development Lifecycle phase.
type PDLCPhase string

// The phases from the AI-PDLC. Progress is not strictly linear: VALIDATE and
// GOVERN can send a project back to SPECIFY, and EVOLVE re-enters DISCOVER.
const (
	PhaseDiscover  PDLCPhase = "DISCOVER"
	PhaseDefine    PDLCPhase = "DEFINE"
	PhaseSpecify   PDLCPhase = "SPECIFY"
	PhaseModel     PDLCPhase = "MODEL"
	PhaseArchitect PDLCPhase = "ARCHITECT"
	PhaseGenerate  PDLCPhase = "GENERATE"
	PhaseValidate  PDLCPhase = "VALIDATE"
	PhaseGovern    PDLCPhase = "GOVERN"
	PhaseBuild     PDLCPhase = "BUILD"
	PhaseTest      PDLCPhase = "TEST"
	PhaseSecure    PDLCPhase = "SECURE"
	PhaseDeploy    PDLCPhase = "DEPLOY"
	PhaseObserve   PDLCPhase = "OBSERVE"
	PhaseReview    PDLCPhase = "REVIEW"
	PhaseEvolve    PDLCPhase = "EVOLVE"
	PhaseRetire    PDLCPhase = "RETIRE"
)

var allPhases = map[PDLCPhase]bool{
	PhaseDiscover: true, PhaseDefine: true, PhaseSpecify: true, PhaseModel: true,
	PhaseArchitect: true, PhaseGenerate: true, PhaseValidate: true, PhaseGovern: true,
	PhaseBuild: true, PhaseTest: true, PhaseSecure: true, PhaseDeploy: true,
	PhaseObserve: true, PhaseReview: true, PhaseEvolve: true, PhaseRetire: true,
}

// Valid reports whether p is a known phase.
func (p PDLCPhase) Valid() bool { return allPhases[p] }

// AllPhases lists the phases in their nominal order.
func AllPhases() []PDLCPhase {
	return []PDLCPhase{
		PhaseDiscover, PhaseDefine, PhaseSpecify, PhaseModel, PhaseArchitect,
		PhaseGenerate, PhaseValidate, PhaseGovern, PhaseBuild, PhaseTest,
		PhaseSecure, PhaseDeploy, PhaseObserve, PhaseReview, PhaseEvolve, PhaseRetire,
	}
}

// Project is a delivery unit within a tenant. It owns an artifact graph.
type Project struct {
	TenantID    types.TenantID
	ID          types.ProjectID
	Key         string
	Name        string
	Description string
	Status      fsm.State
	Phase       PDLCPhase
	Settings    map[string]any
	// GraphVersion is bumped on every graph mutation and embedded in cache keys,
	// so invalidation is atomic with the write rather than a separate step that
	// can be missed.
	GraphVersion int64
	CreatedBy    types.PrincipalID
	CreatedAt    time.Time
	UpdatedAt    time.Time
	Version      int64
}

// NewProject constructs an active project.
func NewProject(tenantID types.TenantID, id types.ProjectID,
	key, name, description string, by types.PrincipalID) (*Project, error) {

	const op = "tenancy.NewProject"

	key = strings.ToUpper(strings.TrimSpace(key))
	if err := types.ValidateProjectKey(key); err != nil {
		return nil, errors.Invalid(op, "project.key_invalid", "%s", err.Error())
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return nil, errors.Invalid(op, "project.name_invalid",
			"A project name is required and must be at most 200 characters.")
	}
	if len(description) > 4000 {
		return nil, errors.Invalid(op, "project.description_too_long",
			"The project description must be at most 4000 characters.")
	}

	now := types.Now()
	return &Project{
		TenantID: tenantID, ID: id, Key: key, Name: name, Description: description,
		Status: ProjectActive, Phase: PhaseDiscover, Settings: map[string]any{},
		GraphVersion: 1, CreatedBy: by, CreatedAt: now, UpdatedAt: now, Version: 1,
	}, nil
}

// Rename updates the display name.
func (p *Project) Rename(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return errors.Invalid("tenancy.Project.Rename", "project.name_invalid",
			"A project name is required and must be at most 200 characters.")
	}
	p.Name = name
	p.UpdatedAt = types.Now()
	return nil
}

// AdvancePhase moves the project to a new AI-PDLC phase.
func (p *Project) AdvancePhase(phase PDLCPhase) error {
	if !phase.Valid() {
		return errors.Invalid("tenancy.Project.AdvancePhase", "project.phase_invalid",
			"%q is not a recognised AI-PDLC phase.", phase)
	}
	p.Phase = phase
	p.UpdatedAt = types.Now()
	return nil
}

// AcceptsWrites reports whether the project may be modified.
func (p *Project) AcceptsWrites() bool { return p.Status == ProjectActive }

// ArtifactPrefix returns the namespace new artifact identifiers use.
func (p *Project) ArtifactPrefix() string { return p.Key }

// ProjectMachine is the project lifecycle.
var ProjectMachine = fsm.New(fsm.Definition[*Project]{
	Name:     "project",
	Initial:  ProjectActive,
	States:   []fsm.State{ProjectActive, ProjectArchived, ProjectPurged},
	Terminal: []fsm.State{ProjectPurged},
	Transitions: []fsm.Transition[*Project]{
		{
			From: []fsm.State{ProjectActive}, Event: EventArchive, To: ProjectArchived,
			Permission: "project:archive",
			EmitEvent:  "project.archived", AuditAction: "project.archive",
			Description: "Stops scheduled work; artifacts remain readable and verifiable.",
		},
		{
			From: []fsm.State{ProjectArchived}, Event: EventRestore, To: ProjectActive,
			Permission: "project:archive",
			EmitEvent:  "project.restored", AuditAction: "project.restore",
		},
		{
			From: []fsm.State{ProjectArchived}, Event: EventPurge, To: ProjectPurged,
			Permission: "tenant:purge",
			EmitEvent:  "project.purged", AuditAction: "project.purge",
			Description: "Requires an executed purge order and a passing legal-hold check.",
		},
	},
})
