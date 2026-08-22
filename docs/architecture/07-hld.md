# SpecForge — High Level Design

**Status:** Baseline v1.0

---

## 1. C4 Level 1 — System context

```mermaid
C4Context
  title SpecForge — System Context
  Person(po, "Product Owner / BA", "Discovers intent, owns PRDs and specs")
  Person(eng, "Architect / Developer / QA", "Consumes specs, reviews generated artifacts")
  Person(gov, "Security / Compliance / Auditor", "Gates, evidence, dispositions")
  Person(ops, "DevOps / SRE", "Pipelines, deployments, incidents")

  System(sf, "SpecForge", "Governed AI-native spec-driven engineering platform")

  System_Ext(idp, "Enterprise IdP", "OIDC / OAuth2 / SAML")
  System_Ext(vcs, "Git provider", "GitHub / GitLab / Bitbucket")
  System_Ext(ci, "CI systems", "GitHub Actions, Jenkins")
  System_Ext(k8s, "Kubernetes clusters", "Customer workload clusters")
  System_Ext(llm, "LLM providers", "Pluggable; simulator by default")
  System_Ext(scan, "Security scanners", "SAST/DAST/SCA/SBOM/IaC/secrets")
  System_Ext(obs, "Telemetry backends", "OTLP → Tempo/Jaeger, Prometheus, Loki")
  System_Ext(notify, "Notification", "Email, Slack, PagerDuty")

  Rel(po, sf, "Discovery, PRD authoring, approval", "HTTPS")
  Rel(eng, sf, "Specs, models, code, drift review", "HTTPS")
  Rel(gov, sf, "Gates, exceptions, audit export", "HTTPS")
  Rel(ops, sf, "Pipelines, deployments, incidents", "HTTPS")
  Rel(sf, idp, "Authenticates principals", "OIDC")
  Rel(sf, vcs, "Ingests repos, receives webhooks, opens PRs", "HTTPS/webhook")
  Rel(sf, ci, "Triggers and observes pipelines", "API/webhook")
  Rel(sf, k8s, "Reads workload state and events", "K8s API (read-mostly)")
  Rel(sf, llm, "Governed inference via AI Gateway", "HTTPS")
  Rel(sf, scan, "Runs and ingests findings", "API")
  Rel(sf, obs, "Exports traces/metrics/logs", "OTLP")
  Rel(sf, notify, "Alerts, escalations, approvals", "API")
```

## 2. C4 Level 2 — Containers

```mermaid
C4Container
  title SpecForge — Containers
  Person(user, "Users")

  Container_Boundary(edge, "Edge") {
    Container(web, "Web App", "Next.js 15, TypeScript, Tailwind, shadcn/ui", "Enterprise UI; server components + BFF route handlers")
  }

  Container_Boundary(plane, "Control Plane") {
    Container(api, "specforge-api", "Go 1.24, modular monolith", "REST v1, SSE/WebSocket, OpenAPI; hosts all bounded contexts as modules")
    Container(worker, "specforge-worker", "Go", "Async: generation, reverse engineering, drift, scans, correlation, projections, outbox relay")
    Container(gw, "specforge-gateway", "Go", "AI Gateway: pre/post guardrail chain, provider routing, budgets, cost ledger")
    Container(gr, "Guardrail sidecars", "Containers", "Presidio, Llama Guard, custom — standard gRPC/HTTP interface")
  }

  Container_Boundary(data, "Data") {
    ContainerDb(pg, "PostgreSQL 16", "RDBMS", "Artifacts, links, governance, audit chain, outbox; RLS per tenant")
    ContainerDb(obj, "Object storage", "S3-compatible", "Content, evidence, source archives, reports; versioned + object-lock")
    ContainerDb(redis, "Redis 7", "Cache", "Sessions ref, permission sets, graph cache, locks, rate limits")
    ContainerQueue(kafka, "Kafka-compatible log", "Redpanda/MSK", "Domain events, projections, DLQ")
  }

  Rel(user, web, "HTTPS")
  Rel(web, api, "REST/SSE, service-to-service token")
  Rel(api, pg, "SQL, RLS session")
  Rel(api, redis, "Cache/locks")
  Rel(api, obj, "Content & evidence")
  Rel(api, kafka, "Outbox relay publishes")
  Rel(worker, kafka, "Consumes")
  Rel(worker, pg, "Projections, findings")
  Rel(api, gw, "Inference requests")
  Rel(worker, gw, "Inference requests")
  Rel(gw, gr, "Guardrail hooks")
```

### 2.1 Container responsibilities

| Container | Responsibility | Scaling | Stateful? |
|-----------|---------------|---------|-----------|
| `web` | UI, BFF, session cookie ↔ token exchange, SSR | HPA on CPU/RPS | No |
| `specforge-api` | All synchronous domain operations, FSM transitions, authz, outbox writes | HPA on RPS + p95 latency | No |
| `specforge-worker` | Event consumers, long jobs (AST, generation, scans), schedulers, outbox relay | KEDA on consumer lag | No (leases in Redis) |
| `specforge-gateway` | Guardrail chain, provider adapters, budgets, circuit breakers, cost/usage ledger | HPA on inflight + p95 | No |
| Guardrail sidecars | One control each, standard interface | Independent HPA | No |

The `worker` runs multiple *roles* selected by flag (`--roles=outbox,drift,ast,scan,projection`), so
noisy neighbours can be split into separate deployments without code changes.

## 3. C4 Level 3 — `specforge-api` components

```mermaid
graph TB
  subgraph Transport
    HTTP["HTTP router<br/>chi + middleware chain"]
    SSE["SSE / WebSocket hub"]
    GRPC["gRPC (internal)"]
  end
  subgraph Middleware
    MW1[request id / trace]
    MW2[auth: JWT/mTLS]
    MW3[tenant resolution]
    MW4[RBAC + ABAC]
    MW5[rate limit / quota]
    MW6[idempotency]
    MW7[security headers / CORS]
    MW8[recovery / timeout]
  end
  subgraph Modules["Bounded-context modules"]
    M1[tenancy]
    M2[identity]
    M3[artifactgraph]
    M4[prd]
    M5[spec]
    M6[model]
    M7[codegen]
    M8[reverse]
    M9[sync]
    M10[governance]
    M11[delivery]
    M12[runtime]
    M13[compliance]
    M14[aiplatform]
    M15[audit]
  end
  subgraph Platform["Platform (shared, no domain logic)"]
    P1[config] --- P2[log] --- P3[otel] --- P4[errors]
    P5[fsm] --- P6[hash/JCS] --- P7[outbox] --- P8[db+RLS]
    P9[objstore] --- P10[cache] --- P11[authz] --- P12[schema registry]
  end
  HTTP --> MW1 --> MW2 --> MW3 --> MW4 --> MW5 --> MW6 --> MW7 --> MW8 --> Modules
  Modules --> Platform
```

**Dependency rule:** `transport → module/application → module/domain`, and
`module/infrastructure → module/domain`. Domain packages import nothing outside the standard library
and `platform/types`. Cross-module calls go through `ports` interfaces only. Enforced by
`make lint-arch`.

## 4. Request lifecycle (representative: approve a PRD)

```mermaid
sequenceDiagram
  autonumber
  participant U as User (Web)
  participant B as BFF (Next.js)
  participant A as specforge-api
  participant G as Governance module
  participant D as PostgreSQL
  participant O as Object storage
  participant K as Event log

  U->>B: POST /prd/PRD-001/approve (cookie)
  B->>A: POST /api/v1/projects/{p}/artifacts/PRD-001/versions/4:approve (Bearer, Idempotency-Key)
  A->>A: JWT verify → tenant resolve → RBAC(artifact:approve) → step-up check
  A->>G: Evaluate bound gates (PRD_GATE, SECURITY_GATE…)
  G->>D: Load policy set + prior dispositions
  G-->>A: ALLOW (+ case IDs)
  A->>A: SoD: approver ≠ sole author
  A->>A: Canonicalize (JCS) → content_hash
  A->>O: PUT content (sha256 key, object-lock)
  A->>O: PUT approval evidence
  A->>D: BEGIN; update version→APPROVED; supersede v3; insert audit (hash-chained); insert outbox(prd.approved); COMMIT
  A-->>B: 200 {version, content_hash, evidence_ref}
  Note over A,K: Outbox relay publishes prd.approved
  A->>K: prd.approved
  K-->>A: consumers: spec generation offer, projections, notifications
```

## 5. Data flow — forward journey

```mermaid
graph LR
  BI[Business intent] -->|AI discovery| PRDD[PRD draft]
  PRDD -->|review + change requests| PRDV[PRD vN]
  PRDV -->|approve + seal| PRDA[(APPROVED PRD<br/>immutable evidence)]
  PRDA --> REQ[Requirements]
  REQ --> SPEC[Specifications<br/>NL + machine-readable]
  SPEC --> BPMN[BPMN 2.0]
  SPEC --> ARCH[C4 architecture]
  ARCH --> API[OpenAPI / proto]
  ARCH --> DATA[ERD / DDL]
  API --> CODE[Go services]
  DATA --> CODE
  CODE --> TEST[Tests]
  CODE --> IAC[Docker / K8s / Helm / Terraform]
  TEST --> GATE{Governance gates}
  IAC --> GATE
  GATE -->|ALLOW| CI[CI/CD]
  CI --> DEP[Deployment]
  DEP --> OBS[Runtime observability]
  OBS -->|failure| RCA[Root cause correlation]
  RCA -.->|traces back to| PRDA
```

## 6. Data flow — reverse journey

```mermaid
graph LR
  REPO[Existing repository] --> ING[Ingestion<br/>clone / archive]
  ING --> AST[Go AST + static analysis<br/>deterministic]
  AST --> FACTS[(Fact base:<br/>packages, routes, deps,<br/>models, events, config)]
  FACTS --> ARCHR[Architecture reconstruction]
  FACTS --> APIR[API contract extraction]
  FACTS --> SEQ[Sequence diagrams]
  FACTS -->|+ LLM narration| SPECR[Reconstructed specifications]
  FACTS -->|flow graph| BPMNR[BPMN where process-shaped]
  SPECR --> MAP[Requirements mapping]
  ARCHR --> GRAPH[(Artifact graph)]
  APIR --> GRAPH
  SPECR --> GRAPH
  BPMNR --> GRAPH
  MAP --> GRAPH
```

**Rule:** `FACTS` are produced only by deterministic analysis. The LLM may narrate, cluster and name
things, but a fact it asserts that is not in the fact base is discarded by the validator.

## 7. Deployment topology (AWS reference)

```mermaid
graph TB
  subgraph Internet
    CF[CloudFront + WAF]
  end
  subgraph VPC
    subgraph Public["Public subnets"]
      ALB[ALB / Ingress NLB]
    end
    subgraph Private["Private subnets — EKS"]
      WEB[web pods]
      API[api pods]
      WRK[worker pods]
      GW[gateway pods + guardrail sidecars]
      OTELC[OTel collector DaemonSet]
    end
    subgraph Data["Private data subnets"]
      RDS[(RDS PostgreSQL 16<br/>Multi-AZ)]
      EC[(ElastiCache Redis<br/>Multi-AZ)]
      MSK[(MSK / Redpanda)]
    end
  end
  S3[(S3: content, evidence WORM, backups)]
  KMS[KMS CMKs per tenant]
  SM[Secrets Manager]
  CF --> ALB --> WEB --> API
  API --> RDS & EC & S3 & MSK
  WRK --> MSK & RDS & S3
  API --> GW
  API & WRK & GW --> OTELC
  RDS -. encrypted .-> KMS
  S3 -. encrypted .-> KMS
  API -. IRSA .-> SM
```

Cloud-neutral ports (`ObjectStore`, `SecretStore`, `KeyManagement`, `EventBus`, `WorkloadInspector`)
isolate every AWS-specific detail in `internal/platform/adapters/aws`. A local adapter set (MinIO,
file secrets, Redpanda, kind) implements the same ports for development.

## 8. Availability & scaling

| Concern | Approach |
|---------|----------|
| Stateless tiers | ≥ 3 replicas across AZs, PDB `minAvailable: 2`, HPA |
| Database | Multi-AZ primary + 2 read replicas; reads for projections/graph queries go to replicas with bounded staleness |
| Cache | Redis cluster mode, AZ-spread; cache loss degrades latency, never correctness |
| Event log | RF=3, `min.insync.replicas=2` |
| Object storage | Cross-region replication for evidence |
| Graph queries | Materialized closure table refreshed by projection + Redis memoization keyed by `(project, graph_version)` |
| Long jobs | Idempotent, resumable, leased; a worker crash re-runs from the last checkpoint |
| Back-pressure | Per-tenant token buckets on inference and generation; 429 with `Retry-After` |

## 9. Key architectural decisions (ADR index)

| ADR | Decision | Rationale |
|-----|----------|-----------|
| ADR-001 | Modular monolith + async worker + separate AI gateway | Twelve contexts, one team-of-teams; distributed transactions avoided; gateway split for latency/blast radius |
| ADR-002 | PostgreSQL as artifact graph store (recursive CTE + closure projection), not a graph DB | Transactional invariants and RLS matter more than traversal elegance at our depth (≤12); one fewer stateful system to secure and back up |
| ADR-003 | RLS enabled in all isolation modes | The isolation code path must never be untested in any deployment mode |
| ADR-004 | Content addressing with JCS canonical JSON | Language-independent, stable hashes; enables offline verification |
| ADR-005 | Transactional outbox over dual-write | Correctness of the audit and event record is non-negotiable |
| ADR-006 | Deterministic analyzers own facts; LLM owns narration and proposals | Brief §42; hallucinated facts would poison the authoritative graph |
| ADR-007 | Guardrails as pluggable containers behind a uniform interface | Presidio/Llama Guard/custom without gateway code changes |
| ADR-008 | BFF pattern; tokens never in browser JS | XSS cannot exfiltrate a bearer token |
| ADR-009 | Simulator provider is a first-class, shipped provider | Deterministic tests and a fully working offline demo; no "TODO: call the LLM" |
| ADR-010 | Generated code carries `@requirement/@spec` annotations | Traceability that survives outside the platform |

Full ADRs in `docs/adr/`.
