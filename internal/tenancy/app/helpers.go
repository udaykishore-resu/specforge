package app

import (
	"context"
	"sort"

	auditdomain "github.com/specforge/specforge/internal/audit/domain"
	"github.com/specforge/specforge/internal/platform/authz"
	"github.com/specforge/specforge/internal/platform/fsm"
	"github.com/specforge/specforge/internal/platform/httpx"
	"github.com/specforge/specforge/internal/platform/obs"
	"github.com/specforge/specforge/internal/platform/outbox"
	"github.com/specforge/specforge/internal/tenancy/domain"
)

// systemPrincipal is the identifier used by platform-driven transitions such as
// provisioning. It is a real principal id so audit records remain attributable.
const systemPrincipal = "00000000-0000-4000-8000-000000000001"

func actorOf(p authz.Principal) auditdomain.Actor {
	a := auditdomain.Actor{
		Kind:        string(p.Kind),
		PrincipalID: p.ID,
		Display:     p.Display,
		Subject:     p.Subject,
		Issuer:      p.Issuer,
		BreakGlass:  p.BreakGlass,
	}
	if p.OnBehalfOf != nil {
		a.OnBehalfOf = *p.OnBehalfOf
	}
	return a
}

func outboxActor(p authz.Principal) outbox.Actor {
	a := outbox.Actor{
		Kind:        string(p.Kind),
		PrincipalID: p.ID.String(),
		Display:     p.Display,
	}
	if p.OnBehalfOf != nil {
		a.OnBehalfOf = p.OnBehalfOf.String()
	}
	return a
}

func correlationFrom(ctx context.Context) outbox.Correlation {
	return outbox.Correlation{
		TraceID:   obs.TraceIDFrom(ctx),
		SpanID:    obs.SpanIDFrom(ctx),
		RequestID: httpx.RequestIDFrom(ctx),
	}
}

// severityFor grades a lifecycle transition for the audit trail. Suspension and
// deletion are the ones an auditor will look for, so they are graded up.
func severityFor(to fsm.State) auditdomain.Severity {
	switch to {
	case domain.TenantSuspended, domain.TenantDeprovisioning:
		return auditdomain.SeverityWarning
	case domain.TenantPurged, domain.TenantFailed:
		return auditdomain.SeverityCritical
	default:
		return auditdomain.SeverityNotice
	}
}

// changedSettingKeys reports which settings changed, without their values.
func changedSettingKeys(before, after domain.Settings) []string {
	var keys []string
	add := func(k string, changed bool) {
		if changed {
			keys = append(keys, k)
		}
	}
	add("four_eyes", before.FourEyes != after.FourEyes)
	add("architect_can_approve_prd", before.ArchitectCanApprovePRD != after.ArchitectCanApprovePRD)
	add("step_up_max_age", before.StepUpMaxAge != after.StepUpMaxAge)
	add("evidence_retention", before.EvidenceRetention != after.EvidenceRetention)
	add("link_auto_accept_threshold", before.LinkAutoAcceptMin != after.LinkAutoAcceptMin)
	add("max_proposals_per_sweep", before.MaxProposalsPerSweep != after.MaxProposalsPerSweep)
	add("max_exception_days", before.MaxExceptionDays != after.MaxExceptionDays)
	add("data_residency", before.DataResidency != after.DataResidency)
	add("guardrail_chain", before.GuardrailChain != after.GuardrailChain)
	add("monthly_token_budget", before.MonthlyTokenBudget != after.MonthlyTokenBudget)
	add("policy_set", before.PolicySet != after.PolicySet)
	add("allowed_ai_providers", !sameStrings(before.AllowedAIProviders, after.AllowedAIProviders))
	sort.Strings(keys)
	return keys
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
