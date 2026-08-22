// Package domain holds the tenancy aggregates: Tenant and Project.
package domain

import (
	"context"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/fsm"
	"github.com/specforge/specforge/internal/platform/types"
)

// Tenant lifecycle states.
const (
	TenantProvisioning   fsm.State = "PROVISIONING"
	TenantActive         fsm.State = "ACTIVE"
	TenantSuspended      fsm.State = "SUSPENDED"
	TenantDeprovisioning fsm.State = "DEPROVISIONING"
	TenantPurged         fsm.State = "PURGED"
	TenantFailed         fsm.State = "FAILED"
)

// Tenant lifecycle events.
const (
	EventProvisioned     fsm.Event = "provisioned"
	EventProvisionFailed fsm.Event = "provision_failed"
	EventSuspend         fsm.Event = "suspend"
	EventReinstate       fsm.Event = "reinstate"
	EventRequestDeletion fsm.Event = "request_deletion"
	EventExecutePurge    fsm.Event = "execute_purge"
)

// Settings are the tenant's governance and platform preferences.
type Settings struct {
	FourEyes               bool          `json:"four_eyes"`
	ArchitectCanApprovePRD bool          `json:"architect_can_approve_prd"`
	StepUpMaxAge           time.Duration `json:"step_up_max_age"`
	EvidenceRetention      time.Duration `json:"evidence_retention"`
	LinkAutoAcceptMin      float64       `json:"link_auto_accept_threshold"`
	MaxProposalsPerSweep   int           `json:"max_proposals_per_sweep"`
	MaxExceptionDays       int           `json:"max_exception_days"`
	DataResidency          string        `json:"data_residency,omitempty"`
	AllowedAIProviders     []string      `json:"allowed_ai_providers,omitempty"`
	GuardrailChain         string        `json:"guardrail_chain,omitempty"`
	MonthlyTokenBudget     int64         `json:"monthly_token_budget,omitempty"`
	PolicySet              string        `json:"policy_set,omitempty"`
}

// DefaultSettings are the secure baseline a new tenant starts from.
//
// Every default here is the stricter option. A tenant can loosen some of them
// deliberately; none of them arrive loose by accident.
func DefaultSettings() Settings {
	return Settings{
		FourEyes:               true,
		ArchitectCanApprovePRD: false,
		StepUpMaxAge:           15 * time.Minute,
		EvidenceRetention:      7 * 365 * 24 * time.Hour,
		LinkAutoAcceptMin:      0.95,
		MaxProposalsPerSweep:   50,
		MaxExceptionDays:       90,
		AllowedAIProviders:     []string{"simulator"},
		GuardrailChain:         "GRC-strict@v2",
		PolicySet:              "builtin@v1",
	}
}

// Validate checks the settings for internally inconsistent values.
func (s Settings) Validate() error {
	const op = "tenancy.Settings.Validate"

	if s.StepUpMaxAge < time.Minute || s.StepUpMaxAge > 8*time.Hour {
		return errors.Invalid(op, "tenant.step_up_max_age_invalid",
			"step_up_max_age must be between one minute and eight hours.")
	}
	if s.EvidenceRetention < 7*365*24*time.Hour {
		// Approval evidence is the platform's regulatory output; a shorter
		// retention would make it useless for the audits it exists to satisfy.
		return errors.Invalid(op, "tenant.evidence_retention_too_short",
			"evidence_retention must be at least seven years.")
	}
	if s.LinkAutoAcceptMin < 0.9 || s.LinkAutoAcceptMin > 1 {
		return errors.Invalid(op, "tenant.link_threshold_invalid",
			"link_auto_accept_threshold must be between 0.9 and 1.0.")
	}
	if s.MaxExceptionDays < 1 || s.MaxExceptionDays > 365 {
		return errors.Invalid(op, "tenant.max_exception_days_invalid",
			"max_exception_days must be between 1 and 365.")
	}
	if s.MaxProposalsPerSweep < 1 || s.MaxProposalsPerSweep > 1000 {
		return errors.Invalid(op, "tenant.max_proposals_invalid",
			"max_proposals_per_sweep must be between 1 and 1000.")
	}
	return nil
}

// Tenant is the isolation boundary that owns everything else.
type Tenant struct {
	ID            types.TenantID
	Slug          string
	Name          string
	Status        fsm.State
	StatusReason  string
	IsolationMode types.IsolationMode
	Region        string
	Settings      Settings
	CreatedBy     types.PrincipalID
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Version       int64
}

// NewTenant constructs a tenant in PROVISIONING.
//
// A tenant is not ACTIVE until its storage, keys and audit chain exist. Creating
// it directly in ACTIVE would let work be accepted for a tenant whose isolation
// boundaries have not been established.
func NewTenant(id types.TenantID, slug, name string, mode types.IsolationMode,
	region string, by types.PrincipalID) (*Tenant, error) {

	const op = "tenancy.NewTenant"

	slug = strings.ToLower(strings.TrimSpace(slug))
	if err := types.ValidateSlug(slug); err != nil {
		return nil, errors.Invalid(op, "tenant.slug_invalid", "%s", err.Error())
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return nil, errors.Invalid(op, "tenant.name_invalid",
			"A tenant name is required and must be at most 200 characters.")
	}
	if !mode.Valid() {
		return nil, errors.Invalid(op, "tenant.isolation_mode_invalid",
			"Isolation mode %q is not recognised.", mode)
	}

	now := types.Now()
	return &Tenant{
		ID: id, Slug: slug, Name: name,
		Status: TenantProvisioning, IsolationMode: mode, Region: region,
		Settings: DefaultSettings(), CreatedBy: by,
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}, nil
}

// Rename changes the display name.
func (t *Tenant) Rename(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return errors.Invalid("tenancy.Rename", "tenant.name_invalid",
			"A tenant name is required and must be at most 200 characters.")
	}
	t.Name = name
	t.UpdatedAt = types.Now()
	return nil
}

// UpdateSettings replaces the tenant settings after validation.
func (t *Tenant) UpdateSettings(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	t.Settings = s
	t.UpdatedAt = types.Now()
	return nil
}

// AcceptsWrites reports whether the tenant may be modified.
func (t *Tenant) AcceptsWrites() bool { return t.Status == TenantActive }

// TenantMachine is the tenant lifecycle. Declared once and validated at init, so
// an unreachable state or a missing audit action fails at startup.
var TenantMachine = fsm.New(fsm.Definition[*Tenant]{
	Name:    "tenant",
	Initial: TenantProvisioning,
	States: []fsm.State{
		TenantProvisioning, TenantActive, TenantSuspended,
		TenantDeprovisioning, TenantPurged, TenantFailed,
	},
	Terminal: []fsm.State{TenantPurged, TenantFailed},
	Transitions: []fsm.Transition[*Tenant]{
		{
			From: []fsm.State{TenantProvisioning}, Event: EventProvisioned, To: TenantActive,
			EmitEvent: "tenant.provisioned", AuditAction: "tenant.provision",
			Description: "Isolation resources are in place; the tenant may accept work.",
		},
		{
			From: []fsm.State{TenantProvisioning}, Event: EventProvisionFailed, To: TenantFailed,
			EmitEvent: "tenant.provision.failed", AuditAction: "tenant.provision_failed",
			Description: "Provisioning failed; the tenant never became usable.",
		},
		{
			From: []fsm.State{TenantActive}, Event: EventSuspend, To: TenantSuspended,
			Permission: "tenant:suspend",
			Guards:     []fsm.Guard[*Tenant]{requireReason},
			EmitEvent:  "tenant.suspended", AuditAction: "tenant.suspend",
			Description: "Writes are blocked; reads remain available.",
		},
		{
			From: []fsm.State{TenantSuspended}, Event: EventReinstate, To: TenantActive,
			Permission: "tenant:suspend",
			EmitEvent:  "tenant.reinstated", AuditAction: "tenant.reinstate",
		},
		{
			From: []fsm.State{TenantActive, TenantSuspended}, Event: EventRequestDeletion,
			To: TenantDeprovisioning, Permission: "tenant:purge",
			Guards:    []fsm.Guard[*Tenant]{requireReason},
			EmitEvent: "tenant.deprovisioning", AuditAction: "tenant.request_deletion",
			Description: "Writes stop; an export bundle is produced before any purge.",
		},
		{
			From: []fsm.State{TenantDeprovisioning}, Event: EventExecutePurge, To: TenantPurged,
			Permission: "tenant:purge",
			EmitEvent:  "tenant.purge.completed", AuditAction: "tenant.purge",
			Description: "Requires two approvers and a passing legal-hold check.",
		},
	},
})

// requireReason refuses a state change that carries no explanation. A suspension
// or deletion with no recorded reason is not defensible after the fact.
func requireReason(_ context.Context, t *Tenant) error {
	if strings.TrimSpace(t.StatusReason) == "" {
		return errors.Invalid("tenancy.requireReason", "tenant.reason_required",
			"A reason is required for this change.")
	}
	return nil
}
