# SpecForge — Implementation Plan

**Status:** Baseline v1.0

Twelve phases, each ending in a demonstrable capability, a test suite, and documentation. No phase
is "done" until its acceptance criteria pass in CI.

---

## Phase 1 — Foundation ✅ *implemented in this revision*

**Delivers:** repository, build system, platform packages, authentication, tenancy, projects,
artifact graph core, audit trail, database, frontend shell, local environment, CI.

| Work | Detail |
|------|--------|
| Platform | config, structured logging, OTel, error model, JCS + hashing, FSM engine, HTTP middleware chain, graceful shutdown, pgx pool with RLS sessions, transactional outbox + relay, Redis cache, object store port + MinIO/S3 adapters, idempotency, rate limiting |
| Identity | OIDC (PKCE, JWKS cache), local dev OIDC provider, API keys, JIT provisioning, role mapping, RBAC bitsets, ABAC/SoD evaluator, step-up auth |
| Tenancy | Tenant + project aggregates, FSMs, provisioning worker, settings |
| Artifact graph | Artifact/version/trace-link aggregates, sealing, immutability triggers, content addressing, hash verification, traversal queries |
| Audit | Hash-chained append-only records, per-tenant sequences, chain verification, anchoring |
| Frontend | Next.js shell, BFF auth, navigation, dashboard, tenants, projects, artifacts, audit views |
| Ops | docker-compose stack, Dockerfiles, Helm chart, Terraform skeleton, GitHub Actions + Jenkinsfile, seed data |

**Acceptance:** create tenant → create project → create artifact → submit → approve → immutable
evidence produced and verifiable → audit chain verifies → cross-tenant access denied at every layer.

## Phase 2 — PRD Studio

AI discovery chat (SSE), structured question flow across the twelve discovery dimensions, PRD
generation, document ingestion (PDF/DOCX/MD/TXT/HTML) with sandboxed parsing, ambiguity/conflict/gap
detection, canonical PRD normalization, version history + diff, change requests, approval with
immutable evidence.
**Acceptance:** Flow A steps 3–11 and Flow B end-to-end; an uploaded PDF becomes a canonical PRD with
detected gaps; approved PRD is byte-immutable and independently verifiable.

## Phase 3 — Specification Engine

Requirements extraction, eight specification classes, stable IDs, Given/When/Then, acceptance
criteria, business/security rules, observability and failure conditions, machine-readable emission
against `spec.v1`, schema validation gate, spec approval.
**Acceptance:** approved PRD yields specifications that validate against the schema, each with ≥1
acceptance criterion and a `DERIVED_FROM` link; regenerating is idempotent for unchanged input.

## Phase 4 — Artifact Graph & Traceability

Closure projection, impact analysis with typed severity, the five traceability queries with path
output, type-aware differs per artifact type, graph cache with atomic invalidation, Artifact
Explorer UI with visual traceability.
**Acceptance:** all five queries answered from the graph in < 500 ms p95 on a 10^6-node fixture,
with full paths and per-hop justification.

## Phase 5 — BPMN & Model Generation

Canonical model layer; BPMN 2.0 generation for process-shaped specs; BPMN validation (soundness,
unreachable tasks, missing end events); BPMN editor (bpmn-js); C4, ERD, OpenAPI, sequence and state
machine generation; representation selection heuristics (do not force BPMN everywhere).
**Acceptance:** a process specification produces valid, importable BPMN 2.0; a data specification
produces an ERD and DDL, not a BPMN.

## Phase 6 — Code Generation

Go service generator: clean architecture, domain/app/infra separation, REST + optional gRPC,
OpenAPI, validation, structured logging, OTel, metrics, health, graceful shutdown, config, secrets;
unit/integration/contract tests; Dockerfile, K8s manifests, Helm, Terraform, CI/CD; traceability
annotations emitted into every generated symbol.
**Acceptance:** generated service compiles, passes its own tests, runs in the local stack, and every
generated file carries `@requirement/@spec` annotations that `make trace-verify` resolves.

## Phase 7 — Reverse Engineering

Git ingestion (clone, archive upload), sandboxed non-executing analysis, Go AST indexer producing
the deterministic fact base (packages, services, routes, dependencies, DB access, models, events,
queues, integrations, config, security controls, observability, deployment topology), architecture
reconstruction, API extraction, sequence diagrams, BPMN where process-shaped, LLM narration bounded
by the fact base, requirements mapping.
**Acceptance:** ingesting SpecForge's own repository reconstructs its architecture and API surface;
every asserted fact is traceable to an AST location; ungrounded LLM claims are dropped.

## Phase 8 — Synchronization

Change detection, incremental impact analysis, spec/BPMN/architecture/API/data/test drift detectors,
proposal generation with schema validation, conflict resolution, loop prevention, consistency score.
**Acceptance:** the reverse journey from brief §41 runs end-to-end; a code change produces drift
findings, a schema-valid proposal, a governance case and — after approval — a new artifact version.

## Phase 9 — CI/CD Integration

GitHub Actions and Jenkins adapters, canonical pipeline model, pipeline generation, webhook
ingestion, run/stage/job/step model, log capture, failure classification, bisect, root-cause
correlation to artifacts.
**Acceptance:** a deliberately broken migration in a demo repo produces the root-cause output shown
in `16-cicd-architecture.md §4.3`, with correct first-failing-commit and affected artifacts.

## Phase 10 — Governance

Policy engine (CEL/Rego), policy sets as artifacts, eight gates, governance cases, dispositions,
exceptions with expiry and compensating controls, Design Authority body with quorum and voting, ADRs,
pre-production compliance orchestration (SAST/DAST/SCA/SBOM/container/IaC/secret/license/PII/API/
coverage/performance/DR/observability), evidence store.
**Acceptance:** every gate returns one of the four decisions with a recorded disposition; an expired
exception re-opens its case and blocks the production gate.

## Phase 11 — AI Guardrails

AI Gateway hardening, guardrail container interface, Presidio, Llama Guard, injection, secret-egress,
grounding and cost guardrails, chains with latency budgets, circuit breakers, fail-open/closed with
disposition enforcement, prompt governance with evaluation gates, usage/cost ledger.
**Acceptance:** the chain honours its latency budget under injected slowness; `fail_open` on a
safety guardrail is refused without a valid disposition; blocked inferences never persist content.

## Phase 12 — Production Observability

Kubernetes inspection (agentless + agent), workload/pod/container views, runtime drift detection,
SLO and error budgets, incident lifecycle, escalation policies, incident timeline, cost monitoring,
DORA dashboards, runtime governance signals.
**Acceptance:** a crashlooping pod in the demo cluster is correlated pod → deployment → pipeline →
commit → code → spec → PRD, and an unacknowledged CRITICAL incident escalates through the chain.

---

## Cross-phase discipline (brief §40)

Before implementing any feature, in this order:

1. Domain model → 2. APIs → 3. Database schema → 4. Events → 5. Security implications →
6. Failure modes → 7. Observability → 8. Tests → 9. Governance implications → 10. Implement →
11. Test → 12. Document.

The template lives at `docs/templates/feature-design.md` and is required in the PR description; the
`CODE_GOVERNANCE_GATE` checks its presence and completeness.

## Rules that hold in every phase

- No placeholder implementations of core functionality. Where an external system cannot run locally,
  a **working simulator** ships (dev OIDC provider, AI simulator provider, local object store,
  local event log, kind-based cluster).
- Every phase adds to the isolation suite and the audit assertions.
- Every phase updates `docs/requirements/register.yaml`, keeping SpecForge traceable in its own
  model — the platform eats its own governance.
