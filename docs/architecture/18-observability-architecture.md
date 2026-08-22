# SpecForge — Observability Architecture

**Status:** Baseline v1.0
Implements brief §26.

---

## 1. Principles

- **OpenTelemetry everywhere**: one SDK, one wire protocol (OTLP), one collector, swappable backends.
- **Correlation is the product.** Traces, metrics, logs, audit records and domain events all carry
  the same correlation keys, so any signal can be pivoted to any other.
- **Telemetry is not audit.** Telemetry is sampled, lossy and short-lived; audit is complete,
  immutable and long-lived. A governance-relevant fact is never *only* in a trace.
- **No sensitive data in telemetry.** Artifact content, prompts, completions, PII and secrets never
  leave in spans or logs; identifiers and hashes only.

## 2. Mandatory correlation attributes

Present on every span, every structured log line, and every domain event (brief §26):

| Key | Type | Always | Notes |
|-----|------|--------|-------|
| `trace_id`, `span_id` | string | ✔ | W3C trace context |
| `tenant.id` | uuid | ✔ | Low-cardinality-safe: hashed in metrics, full in traces/logs |
| `project.id` | uuid | when scoped | |
| `principal.id`, `principal.kind` | string | on request paths | |
| `request.id` | string | ✔ | Echoed as `X-Request-Id` |
| `artifact.id`, `artifact.version`, `artifact.type` | string | on artifact ops | |
| `pipeline.id`, `pipeline.run` | string | on delivery ops | |
| `deployment.id`, `environment` | string | on deploy/runtime ops | |
| `commit.sha`, `branch`, `pr.number` | string | when known | |
| `governance.case_id`, `gate` | string | on gate ops | |
| `ai.inference_id`, `ai.purpose`, `ai.model`, `ai.prompt_version` | string | on AI ops | |

Propagation: W3C `traceparent`/`tracestate` plus a `baggage` header carrying `tenant.id`,
`project.id` and `request.id` so async consumers reconstruct context. Baggage is stripped at the
edge on ingress from untrusted sources (a client cannot inject a tenant into baggage).

## 3. Tracing

Span naming: `<component>.<operation>` — `http.server.request`, `db.query`, `outbox.publish`,
`fsm.transition`, `gate.evaluate`, `ai.request`, `guardrail.pre.presidio-pii`, `ast.index`,
`drift.detect`.

Key traced flows:

| Flow | Span tree |
|------|-----------|
| Approve PRD | `http.server.request` → `authz.evaluate` → `gate.evaluate`(×n) → `artifact.canonicalize` → `objstore.put`(content, evidence) → `db.tx` → `audit.append` → `outbox.append` |
| AI generation | `ai.request` → `ai.prompt.resolve` → `ai.context.assemble` → `guardrail.pre.*` → `ai.provider.call` → `guardrail.post.*` → `ai.validate` |
| Drift sweep | `drift.sweep` → `ast.index` → `drift.detect.spec` → `graph.traverse` → `proposal.generate` → `governance.submit` |
| Pipeline failure | `pipeline.ingest` → `failure.locate` → `failure.classify` → `vcs.bisect` → `graph.correlate` |

Sampling: parent-based, head sampling at 10% for routine reads; **100% for** mutations, gate
evaluations, approvals, AI inference, and anything that errors. Tail sampling in the collector keeps
all traces with errors, high latency, or a `BLOCK` decision.

## 4. Metrics

RED for services, USE for resources, plus domain metrics that make governance measurable.

### 4.1 Service

```
sf_http_requests_total{route,method,status,tenant_hash}
sf_http_request_duration_seconds{route,method}        histogram
sf_http_inflight{route}
sf_db_query_duration_seconds{operation}               histogram
sf_db_pool_connections{state}
sf_cache_operations_total{op,result}
sf_outbox_pending, sf_outbox_publish_duration_seconds, sf_outbox_age_seconds
sf_consumer_lag{topic,group}
```

### 4.2 Domain

```
sf_artifacts_total{type,status,tenant_hash}
sf_artifact_versions_created_total{type,generator_kind}
sf_approvals_total{type,outcome}
sf_integrity_violations_total                          # must be 0; alert on any increase
sf_gate_evaluations_total{gate,decision}
sf_dispositions_total{type}
sf_exceptions_active{severity}, sf_exceptions_expiring_7d
sf_drift_findings_open{drift_type,severity}
sf_consistency_score{project}                          gauge 0-100
sf_orphan_requirements, sf_orphan_code_units, sf_test_gaps
sf_pipeline_runs_total{status}, sf_pipeline_duration_seconds{stage}
sf_deployments_total{env,status}, sf_deployment_lead_time_seconds
sf_incidents_open{severity}, sf_incident_ack_seconds, sf_incident_escalations_total{tier}
sf_ai_requests_total{purpose,provider,model,outcome}
sf_ai_tokens_total{direction}, sf_ai_cost_minor_total{purpose}
sf_ai_schema_failures_total{purpose}
sf_ai_guardrail_blocks_total{guardrail,stage,reason}
sf_audit_records_total, sf_audit_chain_verifications_total{result}
```

Cardinality discipline: `tenant_hash` is a bounded hash bucket, not the raw tenant ID; `route` is the
templated path, never the concrete URL; artifact IDs never appear in metric labels.

### 4.3 SLIs / SLOs

| SLI | SLO |
|-----|-----|
| API availability (non-5xx on mutations) | 99.9% / 30 d |
| API latency p95 (reads) | < 300 ms |
| API latency p95 (mutations) | < 800 ms |
| Traceability query p95 | < 500 ms |
| AI gateway overhead (guardrails + routing) | p95 < 150 ms |
| Outbox publish lag p99 | < 5 s |
| Drift detection latency after `code.changed` p95 | < 60 s |
| Integrity violations | 0 (error budget: none) |

Error budgets are tracked with multi-window burn-rate alerts (1h and 6h windows, 14.4×/6× burn).

## 5. Logging

Structured JSON via `log/slog`, one line per event, no multi-line stack traces in production
(stack traces go into a single `stack` field).

```json
{"time":"2026-08-20T02:41:19.221Z","level":"INFO","msg":"artifact sealed",
 "trace_id":"4bf92f…","span_id":"00f067…","request_id":"req_01J…",
 "tenant_id":"0191…","project_id":"0191…","principal_id":"usr_…",
 "artifact_id":"PRD-001","artifact_version":4,"content_hash":"sha256:c81b…",
 "component":"prd","operation":"approve","duration_ms":412}
```

Rules:

- Levels: `ERROR` (action needed), `WARN` (degraded/self-healed), `INFO` (state changes), `DEBUG`
  (off in production, enable per tenant for a bounded window with an audit record).
- A **redactor** runs before emission: fields tagged `pii`/`secret`, anything matching secret
  patterns, and any raw artifact content are dropped or hashed.
- Error logs always carry the wrapped error chain, the `code`, and the correlation keys.
- Logs are shipped via the collector to the customer's backend; retention 30 d hot, 1 y cold.

## 6. Collector pipeline

```
app (OTLP gRPC) → otel-collector (DaemonSet)
  processors: memory_limiter → k8sattributes → resourcedetection
              → attributes(redact/hash) → tail_sampling → batch
  exporters:  otlp/traces → Tempo|Jaeger
              prometheusremotewrite → Prometheus|Mimir
              otlp/logs → Loki
              otlp → customer BYO endpoint (per tenant, optional)
```

The `attributes` processor is a second line of defence for redaction — the application should never
emit sensitive attributes, and the collector strips them anyway.

Per-tenant telemetry export: a tenant may configure their own OTLP endpoint; the collector routes a
filtered copy of *their* signals only, never another tenant's.

## 7. Dashboards

| Dashboard | Audience | Contents |
|-----------|----------|----------|
| Platform health | SRE | RED metrics, saturation, dependency health, error budget burn |
| Tenant health | Tenant Admin | Their RPS, latency, quota usage, job queue, AI spend |
| Governance posture | Compliance / DA | Gate outcomes, open findings by severity, active and expiring exceptions, dispositions per week |
| Traceability & consistency | Architect / PO | Consistency score trend, orphan requirements, test gaps, drift by type |
| Delivery | DevOps | DORA metrics: lead time, deployment frequency, change failure rate, MTTR |
| AI operations | AI Platform | Requests/tokens/cost by purpose, schema failure rate, guardrail block rate, provider latency and fallbacks |
| Runtime | SRE | Cluster/workload/pod health, restarts, OOMs, correlation entry points |

## 8. Alerting

| Alert | Condition | Severity | Route |
|-------|-----------|----------|-------|
| Integrity violation | `sf_integrity_violations_total` increases | CRITICAL | Security + incident |
| Audit chain verification failed | any failure | CRITICAL | Security + incident |
| API error budget burn | 14.4× over 1 h | HIGH | SRE |
| Outbox lag | `sf_outbox_age_seconds` > 60 s for 5 m | HIGH | SRE |
| Consumer lag | lag > 10k for 10 m | HIGH | SRE |
| Guardrail fail-open active (safety category) | gauge > 0 | HIGH | Security |
| AI schema failure rate | > 5% over 15 m for a purpose | MEDIUM | AI Platform |
| Exception expiring | T-7d | MEDIUM | Owner + Compliance |
| CRITICAL drift open | > 24 h | HIGH | Architect |
| Cost anomaly | > 2σ over baseline | MEDIUM | Tenant Admin |

Every alert links to a runbook section in `23-operational-runbook.md`; an alert without a runbook
entry fails the alert-rule lint in CI.

## 9. Verification

Observability itself is gated: the `DEPLOYMENT_GATE` includes a telemetry conformance check that
asserts the deployed service emits the required spans and metrics with the mandatory correlation
attributes. A service that does not is not "observable enough to deploy".
