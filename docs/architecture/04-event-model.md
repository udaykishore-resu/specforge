# SpecForge — Domain Event Model

**Status:** Baseline v1.0
**Owner:** Design Authority

---

## 1. Principles

1. **Events are facts.** Past tense, immutable, describing something that already happened inside a
   committed transaction. Never a command, never a request.
2. **Transactional outbox, always.** Domain events are written to `outbox_events` in the same
   transaction as the state change. A relay publishes them. There is no `publish()` call in
   application code that can succeed while its transaction rolls back.
3. **At-least-once delivery, idempotent consumers.** Every consumer is keyed by
   `(consumer_group, event_id)` in a processed-events table with a retention window.
4. **Ordering per aggregate.** Partition key is `tenant_id:aggregate_id`. Global ordering is not
   provided and is not required by any consumer.
5. **Tenant-scoped topics.** Physical topics are per event family; the `tenant_id` is in the key and
   in the envelope, and consumers run with tenant context derived from the envelope, never from
   ambient state.
6. **Schema-versioned.** Every event carries `schema` and `schema_version`. Payload schemas live in
   `schemas/events/` and are validated in CI and at publish time in non-production.

## 2. Envelope

```jsonc
{
  "event_id":      "01J9Z8...",          // UUIDv7, unique, used for idempotency
  "event_type":    "prd.approved",
  "schema":        "specforge.event.prd.approved",
  "schema_version": 1,
  "occurred_at":   "2026-08-19T16:40:02.114Z",
  "recorded_at":   "2026-08-19T16:40:02.140Z",
  "tenant_id":     "01919c6e-…",
  "project_id":    "01919c70-…",
  "aggregate": { "type": "Artifact", "id": "PRD-001", "version": 4 },
  "actor":  { "kind": "USER", "principal_id": "usr_…", "display": "r.iyer" },
  "correlation": {
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "span_id":  "00f067aa0ba902b7",
    "causation_id": "01J9Z7…",           // the event or command that caused this one
    "request_id": "req_01J9Z7…",
    "idempotency_key": "…"
  },
  "payload": { /* schema-validated, event-specific */ },
  "payload_hash": "sha256:…"
}
```

`payload_hash` lets consumers and auditors detect payload tampering in the log independently of
broker guarantees.

## 3. Event catalogue

Naming: `<context>.<aggregate>.<past-tense-verb>` — abbreviated where the brief already fixes a name.

### 3.1 Tenancy & Identity

| Event | Payload highlights | Consumers |
|-------|-------------------|-----------|
| `tenant.created` | slug, plan, isolation_mode, region | Provisioner (schema/bucket/topic/keys), Audit, Billing |
| `tenant.suspended` / `tenant.reinstated` | reason, actor | API authz cache invalidation, Notification |
| `tenant.purge.ordered` / `tenant.purge.completed` | order_id, approvers[], legal_hold_status | Purge worker, Audit, Compliance |
| `tenant.settings.updated` | changed_keys[], policy_set_version | Policy cache, Audit |
| `project.created` | key, name, pdlc_phase | Graph bootstrap, Audit |
| `project.archived` | reason | Scheduler (stop drift jobs) |
| `principal.authenticated` | issuer, subject, auth_time, amr[], ip_hash | Audit, anomaly detection |
| `role.assignment.changed` | principal, scope, added[], removed[] | Authz cache, Audit |

### 3.2 Artifact graph

| Event | Payload highlights |
|-------|-------------------|
| `artifact.created` | artifact_id, type, version=1, generator |
| `artifact.version.created` | artifact_id, version, previous_version, change_summary, content_hash |
| `artifact.status.changed` | from, to, transition_event |
| `artifact.sealed` | content_hash, evidence_ref |
| `artifact.superseded` | superseded_version, superseding_version |
| `artifact.integrity.violated` | expected_hash, actual_hash, detector | *(security-critical: auto-incident)* |
| `trace_link.proposed` / `trace_link.accepted` / `trace_link.rejected` / `trace_link.stale` | link_type, from, to, origin, confidence |

### 3.3 PRD Studio

`prd.created`, `prd.updated`, `prd.discovery.started`, `prd.discovery.turn.recorded`,
`prd.document.ingested`, `prd.document.parse.failed`, `prd.analysis.completed`
(ambiguities/conflicts/gaps counts), `prd.change_request.created`, `prd.version.generated`,
`prd.submitted_for_review`, `prd.changes_requested`, **`prd.approved`**, `prd.frozen`,
`prd.superseded`.

`prd.approved` payload is the assurance anchor:

```jsonc
{
  "artifact_id": "PRD-001", "version": 4, "content_hash": "sha256:…",
  "approved_by": "usr_…", "approved_at": "…", "approval_comment": "…",
  "approval_evidence": { "evidence_id": "EVD-00412", "digest": "sha256:…" },
  "gate_decisions": [{ "gate": "PRD_GATE", "decision": "ALLOW", "case_id": "GC-…" }],
  "policy_set_version": "POL-SET@v9",
  "previous_version": 3, "change_summary": "…"
}
```

### 3.4 Specification & modelling

`spec.generated`, `spec.updated`, `spec.approved`, `spec.schema.validation.failed`,
`requirement.created`, `requirement.approved`, `acceptance_criteria.changed`,
`bpmn.generated`, `bpmn.updated`, `bpmn.validation.failed`,
`architecture.generated`, `architecture.updated`,
`api_contract.generated`, `data_model.generated`, `sequence.generated`, `state_machine.generated`.

### 3.5 Code generation & reverse engineering

`code.generation.requested`, `code.generated`, `code.generation.failed`,
`tests.generated`, `repository.connected`, `repository.ingestion.started`,
`repository.ingestion.completed` (packages/routes/deps counts),
`reverse.analysis.completed`, `reverse.spec.reconstructed`, `code.changed` (commit_sha, files[]).

### 3.6 Synchronization

`artifact.drift.detected` (drift_type ∈ SPEC_DRIFT | BPMN_DRIFT | ARCH_DRIFT | API_DRIFT | TEST_GAP |
ORPHAN_REQUIREMENT | ORPHAN_CODE | CONTRADICTION; severity; evidence),
`impact.analysis.completed`, `change_proposal.created`, `change_proposal.submitted`,
`change_proposal.accepted`, `change_proposal.rejected`, `change_proposal.applied`,
`consistency.score.computed`.

### 3.7 Governance

`gate.requested`, `gate.evaluated` (decision, policy results),
`governance.case.opened`, `governance.review.required`, `governance.failed`,
`disposition.recorded`, `exception.granted`, `exception.expiring` (T-7d), `exception.expired`,
`waiver.granted`, `policy.updated`, `design_authority.decision.recorded`.

### 3.8 Delivery

`pipeline.registered`, `pipeline.started`, `pipeline.stage.started`, `pipeline.stage.completed`,
`pipeline.failed`, `pipeline.completed`, `pipeline.root_cause.identified`,
`deployment.started`, `deployment.failed`, `deployment.completed`, `deployment.rolled_back`.

### 3.9 Runtime & incidents

`pod.failed` (reason ∈ OOMKilled | CrashLoopBackOff | ImagePullBackOff | Evicted | ProbeFailure),
`workload.degraded`, `slo.breached`, `runtime.drift.detected` (config/security/dependency),
`incident.created`, `incident.acknowledged`, `incident.escalated`, `incident.mitigated`,
`incident.resolved`, `cost.anomaly.detected`.

### 3.10 Compliance & assurance

`scan.started`, `scan.completed` (kind ∈ SAST | DAST | SCA | SBOM | CONTAINER | IAC | SECRET |
LICENSE | PII), `finding.raised`, `finding.suppressed`, `sbom.generated`,
`evidence.stored`, `compliance.report.generated`.

### 3.11 AI platform

`inference.requested`, `inference.completed` (tokens, latency, cost, model, prompt_version),
`inference.blocked` (stage PRE|POST, guardrail_id, reason_code),
`guardrail.timeout`, `guardrail.circuit_opened`, `guardrail.circuit_closed`,
`prompt.version.published`, `model.binding.changed`, `ai.evaluation.completed`,
`ai.policy.violation.detected`.

### 3.12 Audit

`audit.record.appended` (chain position, record_hash), `audit.chain.anchored` (anchor digest,
object-lock retention), `audit.chain.verification.failed` *(security-critical)*.

## 4. Topic and partition design

| Topic | Key | Partitions | Retention | Notes |
|-------|-----|-----------|-----------|-------|
| `sf.artifact.v1` | `tenant:artifact_id` | 24 | 30 d | Highest volume |
| `sf.prd.v1` | `tenant:artifact_id` | 12 | 90 d | |
| `sf.governance.v1` | `tenant:case_id` | 12 | 365 d | Long retention for assurance |
| `sf.delivery.v1` | `tenant:pipeline_id` | 12 | 90 d | |
| `sf.runtime.v1` | `tenant:workload_id` | 24 | 30 d | |
| `sf.ai.v1` | `tenant:inference_id` | 12 | 90 d | |
| `sf.tenancy.v1` | `tenant` | 6 | ∞ (compacted) | Provisioning |
| `sf.audit.v1` | `tenant` | 12 | ∞ | Mirror of the DB chain for external SIEM |
| `sf.dlq.v1` | original key | 6 | 30 d | Dead letters with failure context |

## 5. Delivery semantics and failure handling

- **Relay**: polls `outbox_events` (indexed on `published_at IS NULL, created_at`) in batches,
  publishes, marks published. Crash between publish and mark → duplicate → consumer idempotency
  absorbs it.
- **Retry**: exponential backoff with full jitter, base 200 ms, cap 30 s, max 8 attempts.
- **DLQ**: after max attempts, the event plus the failure chain moves to `sf.dlq.v1` and raises
  `governance.failed`-class alerting. DLQ entries are replayable from the admin console with an
  audit record.
- **Poison-pill protection**: a consumer that fails on the same `event_id` 3× is circuit-broken for
  that partition rather than blocking the whole group.
- **Ordering guarantee**: per `(tenant, aggregate)` only. Consumers that need cross-aggregate order
  (e.g. correlation) reconcile via `causation_id` and `occurred_at`, and are written to tolerate
  out-of-order arrival.

## 6. Schema evolution rules

| Change | Allowed within a version? |
|--------|---------------------------|
| Add optional field | ✔ |
| Add enum value | ✔ (consumers must have a default branch — enforced by lint) |
| Widen a type | ✔ |
| Remove/rename field, narrow a type, change semantics | ✖ — mint `schema_version + 1` |

When a new version is minted, the publisher **dual-publishes** both versions for one deprecation
window (default 90 days) and the registry marks the old one deprecated. CI fails a build that
consumes a deprecated schema past its sunset date.

## 7. Projections built from events

| Projection | Source events | Purpose |
|-----------|--------------|---------|
| `artifact_graph_read` | artifact.*, trace_link.* | Fast traversal for the five queries |
| `consistency_score` | drift.*, artifact.*, trace_link.* | Per-project score (brief §23) |
| `failure_correlation` | pipeline.*, deployment.*, pod.*, code.changed | Root-cause view (brief §20/§21) |
| `governance_posture` | gate.*, disposition.*, exception.* | Open risk, expiring exceptions |
| `ai_usage_ledger` | inference.* | Tokens, cost, latency per tenant/project/prompt |
| `evidence_index` | evidence.stored, scan.completed | Auditor search |

All projections are rebuildable from the log plus the artifact tables; none is a source of truth.
