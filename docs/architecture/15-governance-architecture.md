# SpecForge — Governance Architecture

**Status:** Baseline v1.0
Implements brief §12, §13, §14, §15, §24, §25.

---

## 1. Model

```
        Subject (artifact | commit | pipeline | deployment | proposal | inference)
                                 │
                            Gate request
                                 ▼
   ┌─────────────── Policy Engine (deterministic) ───────────────┐
   │  PolicySet@version  →  rules (CEL/Rego) over Facts          │
   │  Facts = artifact state + evidence + findings + scores      │
   └──────────────────────────────┬──────────────────────────────┘
                                  ▼
              ALLOW | BLOCK | REVIEW_REQUIRED | EXCEPTION_REQUIRED
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
             Human review               Design Authority
                    └─────────────┬─────────────┘
                                  ▼
                            Disposition (recorded, defensible)
                                  ▼
                        Audit record + domain event
```

Two properties make this defensible: the policy engine is **deterministic** (same facts + same
policy version → same decision, reproducible years later), and every terminal outcome produces
exactly one **Disposition** record.

## 2. Gates

| Gate | Subject | Typical blocking conditions |
|------|---------|----------------------------|
| `PRD_GATE` | PRD version | Unresolved ambiguities above threshold; missing NFR sections; no security/compliance requirements captured; conflicting statements |
| `ARCHITECTURE_GATE` | ARCH version | Undocumented components; unresolved architecture drift; no DR/scalability decision recorded; unapproved technology outside the standards list |
| `SECURITY_GATE` | code/commit/deployment | Critical/high SAST or SCA findings without exception; secret detected; missing authn/authz on a new route; PII field without classification |
| `COMPLIANCE_GATE` | project/release | Missing evidence for a mandated control; retention policy unset; PII processing without a lawful basis record |
| `CODE_GOVERNANCE_GATE` | commit/PR | Traceability annotations missing or dangling; architecture lint violations; generated code modified without a proposal |
| `TESTING_GATE` | release candidate | Acceptance criteria without a verifying test; coverage below the tenant threshold on changed packages; failing contract tests |
| `DEPLOYMENT_GATE` | deployment | Unsigned image; SBOM missing; IaC scan findings; unapproved change window; missing rollback plan |
| `PRODUCTION_GATE` | prod deployment | Any of the above plus: open CRITICAL drift, expired exception in scope, SLO error budget exhausted, unacknowledged CRITICAL incident |

Each gate is a **policy bundle**, not code. Adding a gate is a configuration change with a version;
adding a *rule* to a gate is likewise versioned and audited.

### 2.1 Gate contract

```go
type GateRequest struct {
    TenantID; ProjectID; Gate GateID
    Subject SubjectRef            // artifact ref, commit, pipeline run, deployment…
    Facts   FactBundle            // assembled deterministically by the fact collector
    RequestedBy types.PrincipalID
    IdempotencyKey string
}
type GateDecision struct {
    CaseID types.ULID
    Decision Decision             // ALLOW | BLOCK | REVIEW_REQUIRED | EXCEPTION_REQUIRED
    PolicySetVersion string
    Results []PolicyResult        // rule_id, outcome, severity, message, evidence refs
    RequiredApprovers []RoleOrPrincipal
    ExpiresAt *time.Time          // decisions are cacheable but perishable
}
```

Gate evaluation is **idempotent and pure**: the same `(facts, policy_set_version)` yields the same
decision. The fact bundle is stored with the case, so a decision can be replayed and explained
verbatim during an audit years later.

## 3. Policy engine

- Rules are authored in **CEL** for simple predicates and **Rego** for set-heavy policies; both are
  compiled and cached at policy-set load.
- Policies are artifacts (`POLICY` type) with the full lifecycle: draft → review → approved →
  frozen. A policy set is a versioned bundle of policy artifacts bound to a tenant.
- Rules declare: `id`, `gate`, `severity`, `decision_on_violation`, `message`, `remediation`,
  `evidence_required`, `references` (framework control IDs).
- **Fail closed**: an error evaluating a rule yields `BLOCK` with `code=policy.evaluation_error`,
  never `ALLOW`.
- **No dynamic policy**: policies cannot call out to the network or invoke an LLM. Determinism is
  the point.

Example rule:

```yaml
- id: SEC-004
  gate: SECURITY_GATE
  severity: CRITICAL
  decision_on_violation: EXCEPTION_REQUIRED
  when: |
    facts.scan.sast.findings.exists(f, f.severity in ['CRITICAL','HIGH'] &&
                                       !f.suppressed && !f.has_valid_exception)
  message: "Unresolved high or critical SAST findings."
  remediation: "Fix the finding, or request a security exception with compensating controls."
  evidence_required: [sast_report, sbom]
  references: [ "SOC2:CC7.1", "NIST-SSDF:PW.8", "ISO27001:A.14.2.8" ]
```

## 4. Design Authority

The Design Authority (DA) is a **body**, not a role: a named set of principals with a quorum rule,
scoped to a tenant and optionally to a project.

```yaml
design_authority:
  tenant: acme
  members:
    - { principal: usr_arch1, seat: ARCHITECTURE, voting: true }
    - { principal: usr_sec1,  seat: SECURITY,     voting: true }
    - { principal: usr_cmp1,  seat: COMPLIANCE,   voting: true }
    - { principal: usr_po1,   seat: PRODUCT,      voting: false }
  quorum: { min_voting: 2, required_seats: [SECURITY] }   # security seat mandatory for security items
  decision_sla: 3d
  escalation: [ engineering_lead, cto ]
```

The DA owns (brief §13): architecture correctness, governance correctness, artifact consistency,
security standards, compliance standards, AI governance, technical exceptions, architecture
decisions.

**AI is advisory to the DA.** The platform may attach an AI-generated risk summary, precedent search
and impact analysis to a case; the summary is labelled non-authoritative and the decision record
captures the human votes. A DA decision can never be cast by a service account (SoD-6).

Every DA decision produces an `ArchitectureDecisionRecord` or a `Disposition` (or both), linked into
the artifact graph via `GOVERNS` edges so that the decision is discoverable from the artifacts it
constrains.

## 5. Dispositions (brief §24)

```go
type Disposition struct {
    ID types.ULID; CaseID types.ULID
    TenantID; ProjectID
    Type DispositionType   // APPROVAL | REJECTION | RISK_ACCEPTANCE | EXCEPTION | WAIVER | TEMPORARY_CONTROL
    Decision Decision
    Reason string                  // required, non-empty, min length enforced
    Risk RiskAssessment            // likelihood, impact, inherent, residual
    Impact ImpactStatement         // scope: artifacts, services, environments
    Owner types.PrincipalID        // accountable for the risk
    Approver types.PrincipalID     // who decided
    Approvals []Approval           // for quorum decisions: who voted, when, how
    Evidence []EvidenceRef         // required for RISK_ACCEPTANCE and EXCEPTION
    CompensatingControls []Control
    ExpiresAt *time.Time           // required for EXCEPTION, WAIVER, TEMPORARY_CONTROL
    PolicySetVersion string
    SupersededBy *types.ULID       // corrections are new records
    RecordedAt time.Time
}
```

Validation rules (enforced, not advisory):

- `Reason` must be ≥ 30 characters and must not equal a previously used boilerplate string in the
  same project (a cheap but effective check against rubber-stamping).
- `EXCEPTION`, `WAIVER`, `TEMPORARY_CONTROL` **must** have `ExpiresAt` ≤ tenant maximum (default
  90 days) and at least one `CompensatingControl`.
- `RISK_ACCEPTANCE` requires an `Owner` who holds accountability for the affected service.
- Requester ≠ approver (SoD-2); service accounts cannot approve (SoD-6).
- Dispositions are append-only; a correction records a new disposition with `SupersededBy` set on
  the old one.

Expiry management: a scheduler emits `exception.expiring` at T-7d and T-1d, and `exception.expired`
at expiry, which re-opens the governance case and, if the subject is deployed to production, raises
an incident at the configured severity.

## 6. Pre-production compliance (brief §14)

The compliance context orchestrates scanners and normalizes their output into a single `Finding`
model so policies do not depend on vendor formats.

| Check | Tool class | Gate | Evidence produced |
|-------|-----------|------|-------------------|
| SAST | semgrep/CodeQL | SECURITY | findings + rule versions |
| DAST | ZAP | SECURITY | scan report against an ephemeral env |
| SCA | osv-scanner/grype | SECURITY | vulnerable dependency list |
| SBOM | syft (CycloneDX) | DEPLOYMENT | SBOM attached to the image, signed |
| Container scan | trivy/grype | DEPLOYMENT | image findings |
| IaC scan | checkov/tfsec | DEPLOYMENT | misconfiguration list |
| Secret scan | gitleaks | SECURITY | detections (locations only, never values) |
| License compliance | license classifier | COMPLIANCE | license inventory vs. allowlist |
| PII detection | Presidio | COMPLIANCE | classified fields + data map |
| API security | schema/authz diff | SECURITY | unprotected/changed endpoints |
| Test coverage | go test -cover | TESTING | coverage on changed packages |
| Performance | k6/vegeta | TESTING | latency/throughput vs. NFR thresholds |
| DR validation | restore drill | COMPLIANCE | restore time + integrity report |
| Observability validation | telemetry conformance check | DEPLOYMENT | required spans/metrics present |

Every scan writes an `EVIDENCE` artifact with the tool name, tool version, rule-set version,
invocation parameters and the raw report digest — so a finding (or its absence) is reproducible.

## 7. Production governance (brief §15)

Continuous controls after deployment, each producing findings that feed the same policy engine:

| Monitor | Detects | Signal |
|---------|---------|--------|
| Configuration drift | Live cluster state vs. approved manifests | `runtime.drift.detected{kind:config}` |
| Security drift | Policy/RBAC/network-policy changes, new privileged workloads | `runtime.drift.detected{kind:security}` |
| Dependency drift | New CVEs affecting deployed SBOMs | `finding.raised` |
| Architecture drift | Observed service-call graph vs. the C4 model | `artifact.drift.detected{ARCH_DRIFT}` |
| Specification drift | Behavioural facts vs. approved specs | `artifact.drift.detected{SPEC_DRIFT}` |
| Performance / availability / SLO | SLI vs. objective, error budget burn | `slo.breached` |
| Error rate | Rolling error ratio | incident |
| Cost | Spend anomaly vs. baseline | `cost.anomaly.detected` |
| Compliance | Evidence freshness, expiring exceptions | `exception.expiring` |
| AI behaviour | Block rate, schema-failure rate, refusal rate, cost per purpose | `ai.policy.violation.detected` |

## 8. Governance data model

`governance_cases`, `gate_evaluations`, `policy_results`, `dispositions`, `exceptions`,
`compensating_controls`, `policy_sets`, `design_authority_bodies`, `da_votes`,
`architecture_decision_records`. All tenant-scoped with RLS; dispositions and ADRs are append-only.

## 9. Governance UX principles

- A blocked action always tells the user **which rule**, **why**, **what evidence**, and **how to
  remediate or request an exception** — never a bare "policy violation".
- The exception request form is pre-filled from the failing rule (risk, impact, suggested
  compensating controls) so the path of least resistance produces a *good* disposition record.
- Expiring exceptions appear on the project dashboard and in the owner's queue before they bite.
- Every artifact view shows its governance posture: gates passed, open findings, active exceptions
  with expiry, and the consistency score.
