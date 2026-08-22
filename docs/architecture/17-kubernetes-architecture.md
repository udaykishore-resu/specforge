# SpecForge — Kubernetes Architecture & Runtime Observability

**Status:** Baseline v1.0
Implements brief §21, §22, and the Kubernetes portions of §28, §34.

---

## 1. Two concerns

1. **Running SpecForge on Kubernetes** — the platform's own deployment topology.
2. **Observing the customer's Kubernetes** — reading workload state to correlate runtime failures
   back to commits, artifacts and requirements.

## 2. Platform deployment topology

```
namespace: specforge
  Deployment  specforge-web         3+ replicas, HPA(cpu 60%, rps)
  Deployment  specforge-api         3+ replicas, HPA(cpu 60%, p95 latency)
  Deployment  specforge-worker-*    per role: outbox, drift, ast, scan, projection (KEDA on lag)
  Deployment  specforge-gateway     3+ replicas + guardrail sidecars, HPA(inflight)
  Deployment  guardrail-llamaguard  separate (GPU/CPU-heavy), own HPA
  Job         specforge-migrate     pre-install/pre-upgrade Helm hook, advisory-locked
  CronJob     audit-anchor          hourly
  CronJob     drift-sweep           nightly
  CronJob     exception-expiry      hourly
  CronJob     integrity-sweep       daily
  Service/Ingress, ServiceMonitor, PodMonitor, PrometheusRule
  NetworkPolicy (default deny + explicit allows)
  PodDisruptionBudget minAvailable: 2 per Deployment
```

### 2.1 Pod-level hardening (applies to every workload)

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  fsGroup: 65532
  seccompProfile: { type: RuntimeDefault }
containers:
  - securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: ["ALL"] }
    resources:
      requests: { cpu: 250m, memory: 256Mi }
      limits:   { cpu: 2,    memory: 1Gi }
```

- Distroless base images, non-root UID, no shell.
- `automountServiceAccountToken: false` except where the K8s API is genuinely needed.
- Topology spread across zones; `podAntiAffinity` preferred on hostname.
- `priorityClassName`: `specforge-critical` for api/gateway, `specforge-standard` for workers.

### 2.2 Probes and lifecycle

```yaml
livenessProbe:  { httpGet: { path: /healthz, port: 8080 }, periodSeconds: 10, failureThreshold: 3 }
readinessProbe: { httpGet: { path: /readyz,  port: 8080 }, periodSeconds: 5,  failureThreshold: 2 }
startupProbe:   { httpGet: { path: /healthz, port: 8080 }, failureThreshold: 30, periodSeconds: 2 }
lifecycle: { preStop: { exec: { command: ["/bin/sleep","5"] } } }
terminationGracePeriodSeconds: 40
```

`/healthz` checks only the process. `/readyz` checks DB, Redis, object storage and the broker with
short timeouts and reports per-dependency status — so a readiness failure is diagnosable from the
probe response alone.

### 2.3 NetworkPolicy

Default deny ingress and egress in the namespace, then explicit allows:

| From | To | Ports |
|------|----|-------|
| ingress-nginx | web | 3000 |
| web | api | 8080 |
| api, worker | gateway | 8090 |
| gateway | guardrail sidecars/deployments | 9000 |
| api, worker, gateway | postgres, redis, kafka, object storage endpoints | respective |
| gateway | LLM provider FQDNs (egress allowlist via DNS policy) | 443 |
| guardrail containers | **nothing** (no egress) | — |
| all | otel-collector | 4317 |

The "guardrail containers have no egress" rule is what makes it safe to run third-party guardrail
images: even a malicious guardrail cannot exfiltrate the content it inspects.

### 2.4 Helm chart structure

```
deploy/helm/specforge/
  Chart.yaml  values.yaml  values-dev.yaml  values-staging.yaml  values-prod.yaml
  templates/
    _helpers.tpl  configmap.yaml  secret-refs.yaml (external-secrets)
    web-deployment.yaml  api-deployment.yaml  worker-deployment.yaml  gateway-deployment.yaml
    service.yaml  ingress.yaml  hpa.yaml  pdb.yaml  networkpolicy.yaml
    serviceaccount.yaml  rbac.yaml  migrate-job.yaml  cronjobs.yaml
    servicemonitor.yaml  prometheusrule.yaml  otel-collector.yaml
  tests/  (helm test hooks: connectivity, migration state, readiness)
```

Secrets come from External Secrets Operator referencing AWS Secrets Manager; no secret literal ever
appears in `values.yaml`. `helm lint`, `kubeconform` and `checkov` run in CI.

## 3. Observing customer clusters (brief §21)

### 3.1 Access model

Two supported modes, both **least privilege and read-mostly**:

| Mode | Mechanism | Permissions |
|------|-----------|-------------|
| Agentless | SpecForge connects to the cluster API using a customer-provided credential | A `ClusterRole` with `get/list/watch` on pods, deployments, replicasets, statefulsets, services, events, nodes (metrics only), and `pods/log` scoped to selected namespaces |
| Agent | A lightweight SpecForge agent runs in the customer's cluster and pushes | Same read scope; egress-only to SpecForge; no inbound access to the cluster |

Write access (rollback, scale) is **opt-in per environment**, requires a separate role binding, and
every write is a governed action requiring an approval disposition.

### 3.2 Collected model

```
Cluster → Namespace → Workload (Deployment/StatefulSet/Job) → ReplicaSet → Pod → Container
```

Per level: desired vs. ready replicas; image digest; pod phase, conditions, restart count,
`lastState.terminated.reason` (`OOMKilled`, `Error`, `Completed`), waiting reason
(`CrashLoopBackOff`, `ImagePullBackOff`, `CreateContainerConfigError`), readiness/liveness probe
status, resource requests/limits vs. actual CPU/memory, QoS class, node, events (with `reason`,
`count`, `lastTimestamp`), and log slices around failures.

Metrics come from the customer's Prometheus (or the metrics API) via a read-only query interface;
traces via OTLP if the workloads are instrumented; logs via a scoped `pods/log` read or the
customer's log backend.

### 3.3 Correlation chain (brief §21)

```
Pod (crashlooping)
  → Container image digest
  → Deployment (SpecForge DEPLOYMENT artifact)
  → Pipeline run that produced the image
  → Commit SHA + PR + author
  → Changed files → CODE_UNIT artifacts
  → SPEC / BPMN / REQ via trace links
  → PRD (approved version + approver + evidence)
```

Every hop is a stored relationship, not an inference:

| Hop | How it is known |
|-----|----------------|
| Pod → image digest | Kubernetes status |
| Image digest → pipeline run | Recorded at container build time (digest is the join key) |
| Pipeline run → commit | Recorded at trigger time |
| Commit → code units | AST indexer output for that commit |
| Code units → specs | `@spec` annotations (confidence 1.0) or accepted analyzer links |
| Specs → PRD | `DERIVED_FROM` links created at generation time |

If a hop is missing (e.g. an image built outside SpecForge), the UI says exactly which link is
missing rather than guessing — an unknown provenance is itself a governance finding.

### 3.4 Runtime views

- **Cluster view**: clusters → namespaces → workloads with health rollup.
- **Workload view**: replicas desired/ready/updated/available, rollout history, image digest and its
  provenance, resource headroom, recent events.
- **Pod view**: containers, restart count with reasons, OOM history, probe failures, last 200 log
  lines around each restart, node pressure, related traces.
- **Correlation view**: the chain in §3.3 rendered as a path, with each node clickable.
- **Incident view**: timeline, escalation state, linked artifacts, deployment and commit.

## 4. Runtime governance signals

| Detector | Source | Emits |
|----------|--------|-------|
| Config drift | Live manifest vs. approved `DEPLOYMENT` artifact (normalized diff, ignoring controller-managed fields) | `runtime.drift.detected{config}` |
| Security drift | New privileged pod, changed RBAC, removed NetworkPolicy, disabled probe | `runtime.drift.detected{security}` |
| Dependency drift | New CVE matched against the deployed image's SBOM | `finding.raised` |
| Architecture drift | Observed service-to-service calls (traces) vs. approved C4 relationships | `artifact.drift.detected{ARCH_DRIFT}` |
| SLO | Error budget burn rate (multi-window: 1h/6h) | `slo.breached` |
| Cost | Namespace spend vs. baseline | `cost.anomaly.detected` |

## 5. Incident escalation (brief §22)

```yaml
escalation_policy:
  id: EP-prod-critical
  severities:
    CRITICAL: { ack_sla: 5m,  resolve_sla: 1h }
    HIGH:     { ack_sla: 15m, resolve_sla: 4h }
    MEDIUM:   { ack_sla: 1h,  resolve_sla: 24h }
  chain:
    - { tier: 1, target: oncall_sre,        wait: 5m,  channels: [pagerduty, slack] }
    - { tier: 2, target: engineering_lead,  wait: 10m, channels: [pagerduty, slack, email] }
    - { tier: 3, target: architect,         wait: 15m }
    - { tier: 4, target: incident_commander, wait: 15m }
  auto_actions:
    - { on: "deployment.slo_breach_within_verification_window", action: rollback, requires_disposition: true }
```

Acknowledgement stops escalation. Every escalation step, acknowledgement, mitigation and resolution
appends to an immutable incident timeline that is part of the audit trail. Post-incident review is a
required transition before `CLOSED`, and its output is stored as an `EVIDENCE` artifact linked to
the affected specifications — so incidents feed back into the artifact graph rather than into a
document nobody reads.

## 6. Resilience mechanics

| Mechanism | Where |
|-----------|-------|
| Timeouts | Every outbound call has an explicit deadline derived from the request budget |
| Retries | Idempotent operations only; exponential backoff with full jitter; retry budget capped at 10% of traffic |
| Circuit breakers | Per dependency (DB, Redis, broker, object store, each LLM provider, each guardrail) |
| Bulkheads | Separate pools per dependency class; a slow provider cannot exhaust the DB pool |
| Idempotency | `Idempotency-Key` on all mutations; consumer de-duplication on `event_id` |
| Dead letters | `sf.dlq.v1` with replay tooling and an audit record per replay |
| Graceful degradation | Cache miss → DB; broker down → outbox accumulates (writes still succeed); LLM down → generation queues, platform stays usable; guardrail down → fail closed for AI only, rest of the platform unaffected |
| Back-pressure | Per-tenant token buckets; queue depth surfaced to users with position |
| Health/readiness | §2.2 |
| Backup/restore, DR | `22-disaster-recovery.md` |
