# SpecForge — Product Requirements

**Status:** Baseline v1.0
**Owner:** Design Authority
**Last updated:** 2026-08-20

---

## 1. Problem statement

Enterprise software delivery loses fidelity at every hand-off. Business intent is captured in a
document, re-interpreted into requirements, re-interpreted into designs, re-interpreted into code,
and re-interpreted again into tests and infrastructure. By the time software is running in
production, nobody can answer, with evidence, the question:

> *"Which approved business requirement caused this line of code to exist, and is that code still
> a faithful implementation of it?"*

Regulated enterprises answer this today with manual traceability matrices maintained in
spreadsheets. They are stale on the day they are written.

Generative AI makes the problem worse, not better, when applied naively. An LLM that writes
requirements, specifications and code with no governing artifact model produces *more* unverified
material faster. The bottleneck moves from production to assurance.

## 2. Product thesis

SpecForge is a **governed software engineering platform**, not an LLM wrapper.

- LLMs supply **reasoning and generation**. They are always *proposers*.
- Deterministic subsystems supply **parsing, validation, versioning, hashing, traceability, policy
  evaluation, security, audit, deployment and observation**. They are always *deciders*.
- The **approved artifact graph** is the single authoritative source of truth. No model output
  enters it without passing schema validation, governance gates, and — where policy requires — human
  approval.

## 3. Goals

| # | Goal | Measure of success |
|---|------|--------------------|
| G1 | Convert business intent into an approved, immutable PRD with evidence | Any approved PRD can be re-verified by content hash; approval evidence is tamper-evident |
| G2 | Derive machine-readable specifications from approved PRDs | Every specification has a stable ID and validates against a versioned JSON Schema |
| G3 | Maintain bidirectional traceability across PRD ↔ SPEC ↔ BPMN ↔ ARCH ↔ API ↔ CODE ↔ TEST ↔ PIPELINE ↔ DEPLOYMENT | Platform answers the five traceability queries in §5 in < 500 ms p95 |
| G4 | Reverse engineer existing systems into the same artifact model | Go repositories yield deterministic package/route/dependency facts from AST, not from an LLM |
| G5 | Detect drift in both directions and propose — never apply — corrections | 100% of authoritative-artifact mutations carry a governance disposition record |
| G6 | Enforce governance gates with defensible dispositions | Every gate decision records reason, risk, impact, owner, approver, evidence, expiry |
| G7 | Correlate a production failure back to the requirement that caused the code | Root-cause view links pod → deployment → pipeline → commit → code → spec → PRD |
| G8 | Provide strict tenant isolation suitable for multi-tenant SaaS and single-tenant enterprise | No cross-tenant read is possible even with a forged artifact ID; enforced at DB, storage, cache, event and authz layers |
| G9 | Govern AI itself | Every inference records prompt version, model version, guardrail version, token usage, cost, latency, and passes pre/post-inference hooks within a latency budget |

## 4. Non-goals

- SpecForge does not replace the customer's IDE, VCS, CI runner, or cloud account. It integrates
  with them.
- SpecForge does not attempt to generate arbitrary application languages in v1. Generated code
  targets Go (backend) and Next.js/TypeScript (frontend).
- SpecForge does not auto-merge AI proposals into authoritative artifacts under any configuration.
  "Auto-approve" is a governance policy that records an automated approver — it is never an absence
  of a disposition record.

## 5. The five traceability questions

The platform is considered functional only when it can answer all five from the artifact graph,
without invoking an LLM:

1. *What business requirement caused this code?* — `CODE → SPEC → PRD → REQ` reverse edge walk.
2. *What specifications are affected by this commit?* — `commit → changed files → CODE nodes → SPEC` impact set.
3. *What code implements this requirement?* — `REQ → SPEC → CODE` forward edge walk.
4. *What BPMN process represents this specification?* — `SPEC → BPMN` typed edge.
5. *What deployments are affected by this requirement?* — `REQ → … → PIPELINE → DEPLOYMENT` transitive closure.

## 6. Primary personas

| Persona | Platform role | Primary job |
|---------|--------------|-------------|
| Product Owner | `product_owner` | Drives discovery, owns PRD content, requests changes, approves PRDs |
| Business Analyst | `business_analyst` | Refines requirements, authors/edits specifications, models BPMN |
| Architect | `architect` | Owns architecture artifacts, sits on the Design Authority, rules on exceptions |
| Developer | `developer` | Consumes specs, reviews generated code, commits, resolves drift |
| QA | `qa` | Owns test artifacts and the Testing Gate |
| DevOps | `devops` | Owns pipelines, deployments, Kubernetes topology |
| Security | `security` | Owns Security Gate, threat exceptions, guardrail policy |
| Compliance | `compliance` | Owns Compliance Gate, evidence packs, retention policy |
| Auditor | `auditor` | Read-only across artifacts, dispositions and audit trail; cannot mutate |
| Tenant Admin | `tenant_admin` | Manages tenant users, roles, policies, integrations |
| Platform Admin | `platform_admin` | Operates the platform itself; cannot read tenant artifact *content* without break-glass |
| Viewer | `viewer` | Read-only within granted projects |

## 7. Functional requirements (summary index)

Full requirement register lives in `docs/requirements/register.yaml`. Summary:

- **FR-TEN-*** Tenancy: creation, isolation, settings, per-tenant AI/guardrail/policy configuration.
- **FR-IAM-*** Identity: OIDC/OAuth2, SAML-ready, role mapping, RBAC at tenant and project scope.
- **FR-PRD-*** PRD lifecycle: AI discovery, generation, upload/parse (PDF/DOCX/MD/TXT/HTML),
  ambiguity/conflict/gap detection, versioning, approval, immutability, supersession.
- **FR-SPEC-*** Specification engine: eight specification classes, stable IDs, Given/When/Then,
  acceptance criteria, machine-readable emission against versioned schemas.
- **FR-GRAPH-*** Artifact graph: typed nodes, typed edges, content hashing, version chains, impact analysis.
- **FR-MODEL-*** Model generation: BPMN 2.0, OpenAPI, ERD, C4, sequence, state machines, via a canonical model layer.
- **FR-GEN-*** Code generation: Go services with clean architecture, tests, Docker, K8s, Helm, Terraform, CI/CD.
- **FR-RE-*** Reverse engineering: git ingestion, archive upload, Go AST analysis, discovery, reconstruction.
- **FR-SYNC-*** Synchronization: change detection, impact analysis, drift detection, proposal generation.
- **FR-GOV-*** Governance: gates, policy engine, Design Authority, exceptions, dispositions.
- **FR-SEC-*** Pre-production compliance: SAST/DAST/SCA/SBOM/container/IaC/secret scanning, PII, licenses.
- **FR-AI-*** AI platform: provider abstraction, gateway, guardrails, prompt governance, evaluation.
- **FR-OPS-*** Observability: Kubernetes visibility, failure intelligence, escalation, incident timeline.
- **FR-AUD-*** Audit: immutable, tamper-evident, queryable, exportable.

## 8. Non-functional requirements

| ID | Category | Requirement |
|----|----------|-------------|
| NFR-AVL-001 | Availability | Control plane 99.9% monthly; no single-AZ dependency |
| NFR-PRF-001 | Performance | Artifact graph queries p95 < 500 ms at 10^6 nodes per tenant |
| NFR-PRF-002 | Performance | Guardrail pipeline adds ≤ configured `max_latency` (default 100 ms) to any inference |
| NFR-SCL-001 | Scalability | 10k tenants, 100k projects, horizontal scale of stateless API tier |
| NFR-SEC-001 | Security | Zero Trust; mTLS in mesh, TLS 1.3 at edge; no secret in source or image |
| NFR-SEC-002 | Security | Encryption at rest for DB, object storage, backups; per-tenant KMS key option |
| NFR-ISO-001 | Isolation | Tenant isolation enforced at DB (RLS), object storage prefix+policy, cache namespace, event topic/key, and authorization layer |
| NFR-AUD-001 | Auditability | Audit records append-only and hash-chained; chain verifiable offline |
| NFR-OBS-001 | Observability | Every request carries trace_id, span_id, tenant_id, project_id and, where applicable, artifact_id, pipeline_id, deployment_id, commit_sha |
| NFR-RTO-001 | DR | RTO 4 h, RPO 15 min for control plane; artifact evidence RPO 0 (object-store versioned + replicated) |
| NFR-CMP-001 | Compliance | Evidence retention configurable per tenant, minimum 7 years for approval evidence |
| NFR-AI-001 | AI safety | No tenant data crosses tenant boundary in prompts, embeddings, caches or logs |
| NFR-AI-002 | AI safety | Every AI-produced artifact validated against its schema before persistence; invalid output is quarantined, never stored as an artifact |

## 9. Acceptance criteria (platform-level)

The forward journey and reverse journey defined in the product brief §41 must be demonstrable
end-to-end against seeded demo data, with every step producing a persisted artifact and an audit
record. `docs/acceptance/journey.md` holds the executable acceptance script.

## 10. Release phasing

See `docs/architecture/20-implementation-plan.md`. Phase 1 (Foundation) is implemented in this
repository revision; Phases 2–12 are specified and scaffolded.
