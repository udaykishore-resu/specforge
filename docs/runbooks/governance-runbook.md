# SpecForge — Governance Runbook

**Audience:** Design Authority, Architects, Security, Compliance, Product Owners.
**Purpose:** how governance decisions are actually made, recorded and defended in this platform.

---

## 1. Standing principles

1. **AI proposes. Governance validates. Humans approve.** No exception configuration changes this.
2. **Every decision is defensible.** If you cannot state the reason, risk, impact, owner, evidence
   and expiry, you are not ready to decide.
3. **Approved artifacts are immutable.** You never "fix" an approved PRD; you supersede it.
4. **An exception is a debt with a due date.** Open-ended exceptions are rejected by the engine.
5. **Absence of evidence is a finding.** "It was fine before" is not evidence.

## 2. PRD approval

**Who:** Product Owner (Architect too, if the tenant enables it). Four-eyes on by default.

Checklist before approving:

- [ ] All twelve discovery dimensions addressed (actors, goals, FR, NFR, business rules,
      integrations, security, compliance, availability, scalability, observability, DR).
- [ ] Ambiguity findings resolved or explicitly accepted with a rationale.
- [ ] Conflicts resolved — a conflict carried into specifications multiplies.
- [ ] NFRs are measurable (a number and a window), not adjectives.
- [ ] Security and compliance requirements are present and specific.
- [ ] `change_summary` describes what changed and why, in reviewer-useful terms.
- [ ] `approval_comment` states what you verified, not "LGTM".

On approval the platform seals the version, writes WORM evidence, supersedes the prior approved
version, and emits `prd.approved`. **This is irreversible** — a mistake is corrected by a new
version, never by editing.

## 3. Gate outcomes — what to do with each

| Decision | Meaning | Action |
|----------|---------|--------|
| `ALLOW` | All rules passed | Proceed. The decision and its fact bundle are recorded |
| `BLOCK` | A hard rule failed and no exception path exists | Fix the underlying issue. There is no override permission by design |
| `REVIEW_REQUIRED` | Policy requires human judgement | Route to the named approvers; decide within the SLA; record a disposition |
| `EXCEPTION_REQUIRED` | The rule failed but the policy allows a time-boxed, compensated exception | Follow §4 |

If you find yourself wanting a `gate:override` permission, the correct move is to change the policy
(a versioned, approved change) — not to bypass it for one case.

## 4. Requesting an exception

The request form is pre-filled from the failing rule. You must supply:

| Field | What good looks like |
|-------|---------------------|
| Reason | Why the rule cannot be satisfied now, specifically. ≥ 30 chars; boilerplate reuse is rejected |
| Risk | Likelihood × impact, inherent and residual after controls |
| Impact | Which artifacts, services and environments are affected |
| Owner | The person accountable for the risk — not the requester by default |
| Compensating controls | At least one, concrete and verifiable (e.g. "WAF rule X blocks the vector; alert Y fires on attempts") |
| Expiry | ≤ 90 days by default; shorter for CRITICAL |
| Evidence | Scan output, test results, design notes |

**The requester cannot grant the exception** (SoD-2). Service accounts can never grant (SoD-6).
Security-category exceptions require the Security seat in the Design Authority quorum.

## 5. Design Authority operation

**Composition:** Architecture, Security, Compliance seats voting; Product advisory. Quorum: 2 voting
members, Security seat mandatory for security items.

**Cadence:** weekly standing session; asynchronous decisions allowed within the 3-day SLA for items
below CRITICAL.

**Agenda order:** expiring exceptions → CRITICAL findings and contradictions → architecture
decisions → policy changes → AI governance (prompt/model/guardrail changes) → drift proposals
requiring DA review.

**For each item, record:**

- The decision and the vote.
- The reason, in the DA's own words (an AI-generated summary may be attached but is labelled
  advisory and never substitutes for the recorded reason).
- The risk accepted, if any, and who owns it.
- Compensating controls and their verification method.
- Expiry and review date.
- An ADR when the decision constrains future design.

**AI's role:** the platform attaches a risk summary, precedent search and impact analysis. Treat it
as a briefing note from a capable but unaccountable analyst. Verify anything it asserts about code
against the fact base link it provides.

## 6. Handling drift proposals

1. Read the **drift finding** first, not the proposal. The finding is deterministic; the proposal is
   a suggestion.
2. Confirm the direction of authority: if an approved specification and the code disagree, the
   default is that the *code* is wrong. Changing the specification to match the code is a product
   decision, not a cleanup — it needs the spec owner's approval.
3. Check the proposal's rationale cites the finding IDs it claims to address (the validator enforces
   this, but read it anyway — a rationale that technically cites a finding can still be wrong).
4. For `CONTRADICTION` and `SECURITY_MISMATCH`: never auto-accept, never batch-approve. These are
   the findings that indicate someone's mental model is wrong.
5. Accepting a proposal creates a new artifact *draft* — it still goes through normal approval.

## 7. Policy changes

A policy change is a change to the platform's control environment. Treat it accordingly:

1. Author the change against the policy set in draft.
2. Run it in **shadow mode** against the last 30 days of gate evaluations: the engine reports what
   *would* have changed. A policy change with unknown blast radius is not ready.
3. Review the shadow report with the DA. Look specifically for newly-allowed cases, not just newly
   blocked ones — loosening is the risky direction.
4. Approve, version and publish. `policy.updated` is emitted, caches invalidate, and the new version
   applies to *future* evaluations. Past decisions keep their original policy version — this is what
   makes historical decisions explainable.

## 8. Quarterly governance review

- Consistency score trend per project; investigate any sustained decline.
- Open findings by severity and age; anything CRITICAL older than 30 days needs an explanation.
- Exceptions: how many, how often renewed, who owns them. **Repeatedly renewed exceptions are a
  policy problem, not a project problem** — either the rule is wrong or the remediation is unfunded.
- Orphan requirements and orphan code: both indicate the model and reality have separated.
- Test gaps against approved acceptance criteria.
- AI governance: prompt/model changes, block rates, schema failure rates, human review sampling
  results, cost per artifact.
- DR validation currency (a stale DR validation blocks the compliance gate).
- Audit chain verification results for the period.

## 9. Audit response

When an auditor asks "show me that this deployed behaviour was authorized":

1. Open the runtime object (pod/workload) → **Correlation view**.
2. The chain renders: pod → image digest → deployment → pipeline run → commit → code units →
   specifications → requirements → approved PRD, with each hop's evidence.
3. Export the evidence bundle: `specforge-cli export --project <p> --artifact <id> --with-evidence`.
4. The bundle is independently verifiable offline:
   `specforge-cli verify-evidence --bundle export.tar.zst` recomputes every content hash and
   validates the audit chain **without contacting the platform**. This is the point: the customer
   does not have to trust SpecForge to trust the evidence.

If a hop is missing (e.g. an image built outside the platform), the view says so explicitly. Report
the gap; do not narrate around it.

## 10. Anti-patterns to refuse

| Anti-pattern | Why it is refused |
|--------------|-------------------|
| "Approve it now, we'll document the reason later" | The disposition *is* the decision; an undocumented approval is not an approval |
| Blanket exceptions covering a whole project | Impact must be scoped to be assessable |
| Renewing an exception without re-assessing the risk | Renewal is a new decision, not an extension |
| Editing an approved artifact "because it's a typo" | Supersede it. The immutability is the product |
| Setting a safety guardrail to `fail_open` to unblock a release | Requires a DA disposition with expiry; if you are doing this under release pressure, that *is* the risk |
| Accepting a spec change proposal to make a failing test pass | Inverts the authority order; fix the code or make a deliberate product decision |
| Using `platform_admin` to read tenant content without break-glass | Not possible by design; attempting it is a security event |
