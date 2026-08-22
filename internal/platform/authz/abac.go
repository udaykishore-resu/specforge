package authz

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/platform/errors"
	"github.com/specforge/specforge/internal/platform/types"
)

// PrincipalKind distinguishes humans from machines.
type PrincipalKind string

const (
	KindUser           PrincipalKind = "USER"
	KindServiceAccount PrincipalKind = "SERVICE_ACCOUNT"
	KindSystem         PrincipalKind = "SYSTEM"
)

// Principal is the authenticated caller.
type Principal struct {
	ID          types.PrincipalID
	Kind        PrincipalKind
	TenantID    types.TenantID
	Subject     string
	Issuer      string
	Display     string
	Email       string
	Grants      []Grant
	Permissions Set
	// AuthTime is when the principal last actively authenticated. Step-up checks
	// compare against this, not against token issuance.
	AuthTime time.Time
	// AMR lists the authentication methods used, per RFC 8176.
	AMR []string
	// BreakGlass marks an emergency platform-admin session.
	BreakGlass bool
	// OnBehalfOf is set when a system principal acts for a user.
	OnBehalfOf *types.PrincipalID
	// DesignAuthority is true when the principal sits on the Design Authority
	// body for the tenant or project in scope.
	DesignAuthority bool
}

// HasMFA reports whether the authentication used a second factor.
func (p Principal) HasMFA() bool {
	for _, m := range p.AMR {
		switch strings.ToLower(m) {
		case "mfa", "otp", "hwk", "swk", "sms", "tel", "face", "fpt", "iris", "pin", "user":
			return true
		}
	}
	return false
}

// IsMachine reports whether the principal is non-human.
func (p Principal) IsMachine() bool {
	return p.Kind == KindServiceAccount || p.Kind == KindSystem
}

type principalKey struct{}

// WithPrincipal attaches the authenticated principal.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom reads the authenticated principal.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// ---------------------------------------------------------------------------
// Resources and decisions
// ---------------------------------------------------------------------------

// Resource describes the object of an authorization decision.
type Resource struct {
	Type      string // "artifact", "exception", "deployment", ...
	ID        string
	TenantID  types.TenantID
	ProjectID string
	// CreatedBy is the resource's author, used by four-eyes rules.
	CreatedBy types.PrincipalID
	// Contributors lists everyone who edited the resource, so a four-eyes rule
	// cannot be defeated by having a colleague make one cosmetic edit.
	Contributors []types.PrincipalID
	// RequestedBy is the requester of a governance case, for SoD-2.
	RequestedBy types.PrincipalID
	// ArtifactType, when the resource is an artifact.
	ArtifactType types.ArtifactType
	Attributes   map[string]any
}

// Decision is the outcome of an authorization evaluation, with enough detail to
// explain a denial to an auditor.
type Decision struct {
	Allowed   bool
	RuleID    string
	Reason    string
	Evaluated map[string]any
}

// Policy carries the tenant settings that ABAC rules depend on.
type Policy struct {
	FourEyes               bool
	ArchitectCanApprovePRD bool
	StepUpMaxAge           time.Duration
	ProdDeployFourEyes     bool
	PolicySetVersion       string
}

// DefaultPolicy is the secure baseline.
func DefaultPolicy() Policy {
	return Policy{
		FourEyes:               true,
		ArchitectCanApprovePRD: false,
		StepUpMaxAge:           15 * time.Minute,
		ProdDeployFourEyes:     true,
		PolicySetVersion:       "builtin@v1",
	}
}

// Rule is a segregation-of-duties predicate evaluated for sensitive actions.
type Rule struct {
	ID          string
	Description string
	// Applies reports whether this rule is relevant to the action.
	Applies func(p Permission, res Resource) bool
	// Evaluate returns a denial reason, or "" to allow.
	Evaluate func(pr Principal, res Resource, pol Policy, now time.Time) string
}

// sodRules are the segregation-of-duties rules from
// docs/architecture/05-authorization-model.md §7. They are code rather than
// configuration because weakening one should require a code review, not a
// settings change.
var sodRules = []Rule{
	{
		ID:          "SoD-1",
		Description: "The approver of an artifact version must not be its sole author.",
		Applies: func(p Permission, res Resource) bool {
			return (p == ArtifactApprove || p == PRDApprove || p == SpecApprove) && res.Type == "artifact"
		},
		Evaluate: func(pr Principal, res Resource, pol Policy, _ time.Time) string {
			fourEyes := pol.FourEyes || res.ArtifactType.RequiresFourEyes()
			if !fourEyes {
				return ""
			}
			if res.CreatedBy == "" {
				return ""
			}
			// The approver is allowed if anyone other than them contributed.
			if res.CreatedBy != pr.ID {
				return ""
			}
			for _, c := range res.Contributors {
				if c != pr.ID {
					return ""
				}
			}
			return "Four-eyes control: you are the sole author of this version and cannot also approve it."
		},
	},
	{
		ID:          "SoD-2",
		Description: "The principal requesting an exception may not grant it.",
		Applies: func(p Permission, res Resource) bool {
			return p == ExceptionGrant || p == ProposalApprove || p == FindingSuppress
		},
		Evaluate: func(pr Principal, res Resource, _ Policy, _ time.Time) string {
			if res.RequestedBy != "" && res.RequestedBy == pr.ID {
				return "Segregation of duties: you requested this and cannot also decide it."
			}
			return ""
		},
	},
	{
		ID:          "SoD-3",
		Description: "Exception grants and Design Authority decisions require membership of the body.",
		Applies: func(p Permission, _ Resource) bool {
			return p == ExceptionGrant || p == DesignAuthorityDecide
		},
		Evaluate: func(pr Principal, _ Resource, _ Policy, _ time.Time) string {
			if !pr.DesignAuthority {
				return "This decision requires membership of the Design Authority for this scope."
			}
			return ""
		},
	},
	{
		ID:          "SoD-4",
		Description: "The approver of a production deployment must not be its sole author.",
		Applies: func(p Permission, res Resource) bool {
			return p == DeploymentApprove && res.Type == "deployment"
		},
		Evaluate: func(pr Principal, res Resource, pol Policy, _ time.Time) string {
			if !pol.ProdDeployFourEyes {
				return ""
			}
			env, _ := res.Attributes["environment"].(string)
			if !strings.EqualFold(env, "prod") && !strings.EqualFold(env, "production") {
				return ""
			}
			if res.CreatedBy != pr.ID {
				return ""
			}
			for _, c := range res.Contributors {
				if c != pr.ID {
					return ""
				}
			}
			return "Four-eyes control: you authored every change in this release and cannot also approve its deployment."
		},
	},
	{
		ID:          "SoD-6",
		Description: "Service accounts may never hold approval authority.",
		Applies: func(p Permission, _ Resource) bool {
			return IsApprovalPermission(p)
		},
		Evaluate: func(pr Principal, _ Resource, _ Policy, _ time.Time) string {
			if pr.IsMachine() && pr.OnBehalfOf == nil {
				return "Approval authority cannot be exercised by a service account."
			}
			return ""
		},
	},
	{
		ID:          "StepUp",
		Description: "Sensitive actions require a recent multi-factor authentication.",
		Applies: func(p Permission, _ Resource) bool {
			return RequiresStepUp(p)
		},
		Evaluate: func(pr Principal, _ Resource, pol Policy, now time.Time) string {
			if pr.Kind == KindSystem {
				return ""
			}
			if pr.AuthTime.IsZero() || now.Sub(pr.AuthTime) > pol.StepUpMaxAge {
				return "step_up_required"
			}
			if !pr.HasMFA() {
				return "step_up_required"
			}
			return ""
		},
	},
	{
		ID:          "PRD-Approver",
		Description: "Architects may approve PRDs only when the tenant permits it.",
		Applies: func(p Permission, res Resource) bool {
			return (p == PRDApprove || p == ArtifactApprove) &&
				res.Type == "artifact" && res.ArtifactType == types.ArtifactPRD
		},
		Evaluate: func(pr Principal, _ Resource, pol Policy, _ time.Time) string {
			if pol.ArchitectCanApprovePRD {
				return ""
			}
			hasPO := false
			isArchitect := false
			for _, g := range pr.Grants {
				switch g.Role {
				case RoleProductOwner:
					hasPO = true
				case RoleArchitect:
					isArchitect = true
				}
			}
			if isArchitect && !hasPO {
				return "This tenant restricts PRD approval to the Product Owner role."
			}
			return ""
		},
	},
}

// Evaluator makes authorization decisions.
type Evaluator struct {
	policy Policy
	now    func() time.Time
}

// NewEvaluator builds an evaluator.
func NewEvaluator(pol Policy) *Evaluator {
	return &Evaluator{policy: pol, now: time.Now}
}

// WithClock overrides the clock. Test-only.
func (e *Evaluator) WithClock(now func() time.Time) *Evaluator {
	e.now = now
	return e
}

// Authorize makes the full decision: tenant match, permission, then the ABAC
// rules for sensitive actions.
//
// Order matters. Tenant match is first so that a cross-tenant attempt is denied
// and audited as a tenant mismatch rather than as a missing permission, which
// would hide the more serious signal.
func (e *Evaluator) Authorize(pr Principal, perm Permission, res Resource) Decision {
	if !res.TenantID.Empty() && pr.TenantID != res.TenantID {
		return Decision{
			RuleID: "Tenant-Isolation",
			Reason: "The resource belongs to a different tenant.",
			Evaluated: map[string]any{
				"principal_tenant": pr.TenantID.String(),
				"resource_tenant":  res.TenantID.String(),
			},
		}
	}

	perms := pr.Permissions
	if res.ProjectID != "" && len(pr.Grants) > 0 {
		perms = Resolve(pr.Grants, res.ProjectID)
	}
	if pr.IsMachine() && pr.OnBehalfOf == nil {
		perms = ServiceAccountSet(perms)
	}

	if !perms.Has(perm) {
		return Decision{
			RuleID: "RBAC",
			Reason: fmt.Sprintf("The %s permission is required.", perm),
			Evaluated: map[string]any{
				"required":   perm.String(),
				"project_id": res.ProjectID,
			},
		}
	}

	now := e.now()
	for _, rule := range sodRules {
		if rule.Applies == nil || !rule.Applies(perm, res) {
			continue
		}
		if reason := rule.Evaluate(pr, res, e.policy, now); reason != "" {
			return Decision{
				RuleID: rule.ID,
				Reason: reason,
				Evaluated: map[string]any{
					"rule":        rule.ID,
					"description": rule.Description,
					"permission":  perm.String(),
				},
			}
		}
	}

	return Decision{
		Allowed:   true,
		RuleID:    "RBAC+SoD",
		Reason:    "granted",
		Evaluated: map[string]any{"permission": perm.String(), "project_id": res.ProjectID},
	}
}

// Require converts a decision into an error suitable for the transport layer.
func (e *Evaluator) Require(pr Principal, perm Permission, res Resource) error {
	const op = "authz.Require"
	d := e.Authorize(pr, perm, res)
	if d.Allowed {
		return nil
	}
	if d.Reason == "step_up_required" {
		return errors.Unauthorized(op, "auth.step_up_required",
			"This action requires a recent multi-factor authentication.").
			WithDetail("rule", d.RuleID).
			WithDetail("permission", perm.String())
	}
	return errors.Forbidden(op, denialCode(d.RuleID), d.Reason).
		WithDetail("rule", d.RuleID).
		WithDetail("permission", perm.String())
}

func denialCode(ruleID string) string {
	switch {
	case ruleID == "Tenant-Isolation":
		return "authz.tenant_mismatch"
	case ruleID == "RBAC":
		return "authz.denied"
	case strings.HasPrefix(ruleID, "SoD"):
		return "sod.violation"
	default:
		return "authz.denied"
	}
}

// RuleCatalogue lists the SoD rules, for documentation and the governance UI.
func RuleCatalogue() []struct{ ID, Description string } {
	out := make([]struct{ ID, Description string }, 0, len(sodRules))
	for _, r := range sodRules {
		out = append(out, struct{ ID, Description string }{r.ID, r.Description})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
