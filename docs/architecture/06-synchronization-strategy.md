# SpecForge — Bidirectional Synchronization Strategy

**Status:** Baseline v1.0
**Owner:** Design Authority

Implements brief §9, §10, §23. This is the subsystem that keeps PRD, specification, process model,
architecture, code and tests from silently diverging — and the one where the "AI proposes, governance
validates, human approves" rule is mechanically enforced.

---

## 1. The non-negotiable rule

```
  Detector (deterministic)  →  Analyzer (deterministic)  →  Proposer (may use LLM)
        →  Governance (deterministic policy)  →  Human approval (where policy requires)
        →  New artifact version (through the artifact FSM)
```

The synchronization engine has **no write access** to authoritative artifacts. Its only outputs are
`DriftFinding` and `ChangeProposal` records. Applying a proposal is a Governance-context operation
that goes through `artifact.revise → DRAFT → … → APPROVED` like any other change.

Enforced structurally: the `sync` module imports the artifact graph's **read** port only. The
architecture lint rule `sync-must-not-import-artifact-write` fails the build otherwise.

## 2. Synchronized relationships

| Pair | Direction | What "consistent" means | Detector |
|------|-----------|------------------------|----------|
| PRD ↔ SPEC | both | Every approved PRD requirement has ≥1 non-stale derived spec; every spec traces to a live PRD statement | Coverage analyzer over `DERIVED_FROM`/`SATISFIES` links + PRD statement segmentation |
| SPEC ↔ BPMN | both | Every spec with process semantics has a BPMN whose task/gateway set covers its Given/When/Then steps | BPMN element diff vs. spec step extraction |
| SPEC ↔ ARCHITECTURE | both | Every spec's named component exists in the C4 model; every component traces to ≥1 spec | C4 element set diff |
| ARCHITECTURE ↔ CODE | both | Every architectural component maps to ≥1 package/service; no undeclared cross-component dependency | Go AST import graph vs. C4 relationships |
| SPEC ↔ CODE | both | Every spec has ≥1 `CODE` unit with a matching `@spec` annotation; every annotated symbol references a live spec | Annotation scanner (deterministic, confidence 1.0) |
| API_CONTRACT ↔ CODE | both | Routes in code == operations in OpenAPI (path, method, params, status codes) | Route extractor vs. OpenAPI parse |
| DATA_MODEL ↔ CODE/DB | both | ERD entities == migration DDL == struct tags | Migration parser + struct reflection |
| CODE ↔ TESTS | both | Every spec acceptance criterion has ≥1 test referencing it; every test references a live criterion | Test annotation scan + coverage map |
| SPEC ↔ DEPLOYMENT | forward | NFR thresholds (SLO, replicas, resources) present in manifests | Manifest parser vs. NFR spec fields |

## 3. Drift taxonomy

| `drift_type` | Meaning | Default severity |
|---|---|---|
| `SPEC_DRIFT` | Code behaviour diverges from its specification | HIGH |
| `BPMN_DRIFT` | Implemented flow diverges from the modelled process | HIGH |
| `ARCH_DRIFT` | Dependency or component structure violates architecture | HIGH |
| `API_DRIFT` | Implementation and contract disagree | HIGH (breaking) / MEDIUM (additive) |
| `DATA_DRIFT` | Schema and data model disagree | HIGH |
| `TEST_GAP` | Acceptance criterion with no verifying test | MEDIUM |
| `ORPHAN_REQUIREMENT` | Approved requirement with no implementing code | MEDIUM |
| `ORPHAN_CODE` | Code with no traceable requirement | LOW (informational in brownfield, MEDIUM in greenfield) |
| `STALE_LINK` | Link endpoint version superseded and content materially changed | MEDIUM |
| `CONTRADICTION` | Two approved artifacts assert incompatible things | CRITICAL |
| `SECURITY_MISMATCH` | Security spec control absent in code/manifests | CRITICAL |
| `COMPLIANCE_MISMATCH` | Compliance obligation without evidence | HIGH |

Severity is then adjusted by policy: artifact criticality label, environment (prod vs. dev), and
whether the counterpart artifact is `APPROVED` or `FROZEN`.

## 4. Trigger model

| Trigger | Latency target | Scope |
|---------|---------------|-------|
| `code.changed` (webhook: push, PR open/sync, merge) | < 60 s | Incremental — only artifacts reachable from changed files |
| `artifact.version.created` on an approved artifact | < 30 s | Incremental — reachable counterparts |
| Scheduled full sweep | nightly | Whole project; recomputes the consistency score from scratch |
| Manual `sync:run` | on demand | Selectable scope |
| Pre-merge check (PR gate) | < 5 min | Diff-scoped, posts a check run |

Incremental runs are the norm; the nightly sweep exists to catch anything the incremental path
missed and to detect decay (expired exceptions, superseded endpoints).

## 5. The eight-step pipeline (brief §9)

### Step 1 — Detect changed files
From the VCS webhook: base and head SHAs, changed paths, PR metadata. For non-VCS triggers, the
changed artifact version and its type-aware diff.

### Step 2 — Identify affected artifacts
Deterministic mapping:
- path + symbol range → `CODE_UNIT` artifacts (maintained by the AST indexer, not by heuristics);
- `CODE_UNIT` → linked `SPEC`, `API`, `ARCH`, `TEST` via `ACCEPTED` trace links;
- transitive closure bounded by depth and by link type (see `02-canonical-artifact-model.md §5`).

### Step 3 — Impact analysis
Compute the typed reachability set with per-hop severity (`02 §6`). Output: `impact.analysis.completed`
with the artifact set, path justification per artifact, and an aggregate blast-radius score.

### Step 4–6 — Detect drift (spec, BPMN, architecture)
Each detector is a pure function `(subjectVersion, counterpartVersion, config) → []DriftFinding`.
Detectors are deterministic and unit-tested with golden fixtures. Concretely:

- **Spec drift**: extract behavioural facts from code (routes, guards, validation rules, error paths,
  emitted events, persistence calls) via AST; compare against the spec's machine-readable
  `given/when/then` and `business_rules`. A mismatch is reported with both sides quoted.
- **BPMN drift**: build a flow graph from the code (handler → service → external calls, with
  branch conditions) and structurally compare to the BPMN task/gateway/event graph. Report added,
  removed and reordered elements.
- **Architecture drift**: compare the Go import graph and service call graph to the C4 model's
  allowed relationships. Any edge not permitted by the model is a violation with the exact import.

The LLM is **not** in this step. It cannot be: a hallucinated drift finding would either block a
correct pipeline or, worse, justify a spurious specification change.

### Step 7 — Generate proposed updates
This is where the LLM is used, under constraints:
- Input: the drift finding, both artifact versions, and the project's style/schema context. Never
  raw repository content beyond the cited spans.
- Output: a **structured proposal** — a candidate new artifact payload — that must validate against
  the target `content_schema` before it is stored. Invalid output is retried once, then quarantined
  as `proposal.generation.failed`; it is never stored as a proposal.
- Every proposal records `prompt_version`, `model`, `guardrail_chain_version`, `inference_id`.
- Proposals carry a **rendered diff** against the current version and a rationale that must cite the
  drift finding IDs it addresses. A rationale citing no finding is rejected by the validator.

### Step 8 — Governance
`ChangeProposal` enters the FSM in `03-state-machines.md §3`. Routing policy decides:

| Condition | Route |
|-----------|-------|
| Drift severity ≥ HIGH, or target is `APPROVED`/`FROZEN` | `REVIEW_REQUIRED` — human approval mandatory |
| Target artifact type ∈ {POLICY, SECURITY spec, ARCH} | Design Authority review |
| Severity ≤ LOW and target is `DRAFT` and proposal only adds annotations/links | May be auto-accepted, recording an automated approver in the disposition |
| Contradiction or security mismatch | `EXCEPTION_REQUIRED` — blocks the relevant gate until dispositioned |

## 6. Conflict resolution

When both sides of a relationship changed since their last agreed pair (`(spec@v3, code@sha1)`):

1. Identify the **agreement baseline** — the last pair with an `ACCEPTED` link and no open drift.
2. Compute both diffs from the baseline.
3. Classify:
   - **Non-overlapping** → generate two independent proposals.
   - **Overlapping, compatible** → single merged proposal.
   - **Overlapping, contradictory** → `CONTRADICTION` finding; no auto-proposal; escalate to the
     owning role (spec owner and code owner) with both diffs presented side by side.
4. **Authority precedence** when policy must break a tie: `APPROVED PRD > APPROVED SPEC > ARCH >
   CODE`. Code never wins against an approved specification automatically; it can only produce a
   proposal to change the specification, which a human must approve. This preserves the brief's
   §42 principle.

## 7. Loop prevention

- Every proposal-applied version is tagged `origin=SYNC` with the `proposal_id`.
- The detector ignores drift whose *sole* cause is a version created by the same proposal within the
  same sweep generation (`generation_id`), preventing A-updates-B-updates-A cycles.
- A per-project circuit breaker halts synchronization after `max_proposals_per_sweep` (default 50)
  and raises `governance.failed` for human triage, rather than flooding reviewers.

## 8. Consistency score (brief §23)

Computed per project on every sweep, in `[0, 100]`, as a weighted penalty model:

```
score = 100 · Π_d ( 1 − w_d · penalty_d )

penalty_d = min(1, open_findings_d_weighted / normalizer_d)
weighted  = Σ severity_weight(f)   for open, non-excepted findings of dimension d
```

Dimensions and weights (tenant-configurable, defaults shown):

| Dimension | Weight | Normalizer |
|-----------|--------|-----------|
| Requirement coverage (PRD→SPEC) | 0.20 | count of approved requirements |
| Specification implementation (SPEC→CODE) | 0.20 | count of approved specs |
| Test verification (SPEC→TEST) | 0.15 | count of acceptance criteria |
| Process fidelity (SPEC↔BPMN) | 0.10 | count of process specs |
| Architecture conformance | 0.15 | count of architecture relationships |
| API contract conformance | 0.10 | count of operations |
| Security & compliance mapping | 0.10 | count of security controls |

Severity weights: CRITICAL 8, HIGH 4, MEDIUM 2, LOW 1, INFO 0.
Findings covered by an **unexpired** exception are excluded from the numerator but surfaced
separately as *accepted risk*, so the score is never gamed by silently waiving problems — the UI
always shows `score` next to `accepted_risk_count`.

The score is a projection, recomputed from findings; it is never stored as an authoritative value.

## 9. Code traceability metadata (brief §10)

Generated and human-maintained code carries machine-readable annotations:

```go
// @requirement REQ-AUTH-002
// @spec        SPEC-AUTH-001
// @process     BPMN-AUTH-001
// @criteria    AC-3,AC-4
func (s *Service) StepUpAuthenticate(ctx context.Context, in StepUpInput) (StepUpResult, error) {
```

- The annotation scanner is a deterministic Go AST visitor producing `CODE_UNIT` artifacts with
  `(repo, path, symbol, start_line, end_line, commit_sha)` and links with confidence 1.0.
- `make trace-verify` fails if an annotation references an unknown or abandoned artifact ID, or if
  an approved spec has no annotated implementation (configurable severity).
- A pre-commit hook and a PR check keep annotations honest at author time rather than at audit time.
- For languages without annotations, links fall back to `ANALYZER` (path/package convention) with
  confidence < 1.0 and remain `PROPOSED` until accepted.

## 10. Reverse-flow acceptance scenario

The brief's §41 reverse journey, mapped to this design:

| Brief step | Implementation |
|-----------|----------------|
| Code Change | `code.changed` from VCS webhook |
| Detect Change | Step 1: changed-file resolution + AST re-index of touched packages |
| Impact Analysis | Step 3: typed reachability set with path justification |
| Spec Drift | Step 4: behavioural fact extraction vs. machine-readable spec |
| BPMN Drift | Step 5: flow-graph structural comparison |
| Proposed Updates | Step 7: schema-validated LLM proposal with rendered diff and cited findings |
| Governance Review | `ChangeProposal` FSM → `GOVERNANCE_REVIEW`, policy-routed |
| Approval | Human approval with SoD checks and step-up auth |
| New Version | `artifact.revise` → new version sealed with `origin=SYNC`, `proposal_id`, full provenance |

Every step emits its event (`04-event-model.md §3.6`) and an audit record, so the reverse journey is
reconstructible from the audit trail alone.
