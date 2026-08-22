# SpecForge — Canonical Artifact Model

**Status:** Baseline v1.0
**Owner:** Design Authority

This is the constitutional document of the platform. Every other subsystem is downstream of it.

---

## 1. Principles

1. **Content addressing.** An artifact version is identified by `(tenant, project, artifact_id,
   version)` and *pinned* by `content_hash`. If the bytes change, the hash changes, and the version
   is invalid — not updated.
2. **Immutability by status.** `DRAFT` versions are mutable working copies. Every other status is
   byte-immutable. There is no "edit approved artifact" code path anywhere in the system.
3. **Append-only history.** Versions are never deleted. `SUPERSEDED` and `RETIRED` are statuses, not
   deletions. Physical deletion happens only through an executed purge order under legal-hold check.
4. **Typed edges, not implicit joins.** Relationships are first-class `TraceLink` rows with a type,
   an origin, a confidence and a status. There is no implicit "this spec probably belongs to that PRD".
5. **Provenance is mandatory.** Every version records *what produced it*: a human principal, a
   deterministic analyzer (with version), or an inference (with prompt/model/guardrail versions).
6. **Canonical serialization.** All hashing uses RFC 8785 JSON Canonicalization Scheme over the
   artifact's canonical form. Rendered forms (Markdown, XML, diagrams) are derived and separately
   digested but never authoritative for the hash.

## 2. Canonical form

```jsonc
{
  "schema": "specforge.artifact.v1",          // envelope schema version
  "artifact_id": "SPEC-AUTH-001",
  "artifact_type": "SPECIFICATION",
  "version": 3,
  "tenant_id": "01919c6e-....",
  "project_id": "01919c70-....",
  "status": "APPROVED",                        // recorded, but NOT hashed (see the hash rule)
  "content_schema": "specforge.spec.v1",       // payload schema version
  "content": { /* type-specific payload, canonicalized */ },
  "parent_artifact": { "artifact_id": "PRD-001", "version": 4 },   // structural parent
  "source_artifact": { "artifact_id": "PRD-001", "version": 4 },   // what it was derived from
  "previous_version": 2,
  "change_summary": "Added MFA step-up acceptance criteria AC-4, AC-5.",
  "created_by":  { "principal_id": "usr_...", "display": "a.nolan", "kind": "USER" },
  "created_at":  "2026-08-19T14:02:11Z",
  "approved_by": { "principal_id": "usr_...", "display": "r.iyer",  "kind": "USER" },
  "approved_at": "2026-08-19T16:40:02Z",
  "approval_comment": "Security review complete; SEC-GATE passed with 0 blocking findings.",
  "approval_evidence": {
    "evidence_id": "EVD-00412",
    "digest": "sha256:9f2c...",
    "media_type": "application/vnd.specforge.approval+json",
    "storage_ref": "s3://sf-evidence/<tenant>/<project>/EVD-00412.json"
  },
  "generator": {
    "kind": "INFERENCE",                        // USER | ANALYZER | INFERENCE | IMPORT
    "prompt_version": "PRM-0007@v4",
    "model": "sim-reasoner-v1",
    "provider": "simulator",
    "temperature": 0.2,
    "guardrail_chain_version": "GRC-default@v2",
    "inference_id": "inf_01J...",
    "input_artifacts": [{ "artifact_id": "PRD-001", "version": 4 }]
  },
  "traceability_links": [
    { "link_type": "DERIVED_FROM",  "to": { "artifact_id": "PRD-001",  "version": 4 } },
    { "link_type": "SATISFIES",     "to": { "artifact_id": "REQ-AUTH-002", "version": 1 } },
    { "link_type": "REPRESENTED_BY","to": { "artifact_id": "BPMN-AUTH-001", "version": 2 } }
  ],
  "labels": { "domain": "identity", "criticality": "high" },
  "content_hash": "sha256:c81b...".              // excluded from its own computation
}
```

**Hash rule.**

```
content_hash = SHA-256(JCS(envelope minus {content_hash, status, approval_*, traceability_links}))
```

What is excluded matters as much as what is included:

| Excluded | Why |
|----------|-----|
| `status` | Lifecycle state changes as a version moves through review. Including it would change the hash at every transition and destroy the property that actually matters: **the hash of an approved version is the hash of exactly the bytes that were submitted for review, unchanged**. Status is guarded by the state machine, the `sf_enforce_version_immutability` trigger and the audit chain instead. |
| `approved_by`, `approved_at`, `approval_comment`, `approval_evidence` | The approval attests to the content, so the content hash must not depend on the attestation. The evidence pins the hash, not the other way round. |
| `traceability_links` | Links are independent aggregates that may be added after a version is sealed; including them would make the seal unstable. Link integrity is protected by the audit chain. |
| `content_hash` | It is the output. |

The sealing code asserts this rather than assuming it: `SealApproval` recomputes the hash after
setting the approval fields and fails loudly if the value changed. A future edit to the envelope
that reintroduced this coupling would break at the seal, not silently at the next read.

## 3. Artifact envelope — required fields

Mandated by the product brief §5 and enforced by `internal/platform/artifact.Validate`:

| Field | Required | Immutable after seal | Notes |
|-------|----------|----------------------|-------|
| `artifact_id` | ✔ | ✔ | Project-scoped, human-meaningful, never reused |
| `artifact_type` | ✔ | ✔ | From the taxonomy in `01-domain-model.md §5` |
| `version` | ✔ | ✔ | Gapless, starts at 1 |
| `tenant_id` | ✔ | ✔ | Isolation key; present in every index |
| `project_id` | ✔ | ✔ | |
| `parent_artifact` | ✖ | ✔ | Structural containment (e.g. spec → PRD) |
| `source_artifact` | ✖ | ✔ | Derivation source; may differ from parent |
| `content_hash` | ✔ | ✔ | Verified on every read |
| `status` | ✔ | ✖→✔ | Mutable only along the state machine; frozen at terminal states. Not covered by `content_hash` |
| `created_by`, `created_at` | ✔ | ✔ | |
| `traceability_links` | ✔ (may be empty) | ✖ | Managed as separate aggregates |

PRD-specific additional mandatory fields at `APPROVED` (brief §3): `approved_by`, `approved_at`,
`approval_comment`, `approval_evidence`, `previous_version`, `change_summary`.

## 4. Trace link types

Directed edges, `from → to`. Each has a defined inverse used for reverse walks.

| `link_type` | Semantics | Typical from → to | Inverse |
|-------------|-----------|-------------------|---------|
| `DERIVED_FROM` | The source was transformed into this | SPEC → PRD | `DERIVES` |
| `SATISFIES` | This artifact fulfils that requirement | CODE → SPEC, SPEC → REQ | `SATISFIED_BY` |
| `IMPLEMENTS` | Executable realization | CODE → API_CONTRACT | `IMPLEMENTED_BY` |
| `REPRESENTED_BY` | Alternate modelling of the same intent | SPEC → BPMN | `REPRESENTS` |
| `VERIFIES` | Test coverage relation | TEST → SPEC | `VERIFIED_BY` |
| `REALIZED_BY` | Design → deployable | ARCH → CODE | `REALIZES` |
| `DEPLOYS` | Delivery relation | PIPELINE → DEPLOYMENT | `DEPLOYED_BY` |
| `CONTAINS` | Structural composition | ARCH → ARCH (component) | `CONTAINED_BY` |
| `DEPENDS_ON` | Runtime/build dependency | CODE → CODE | `DEPENDED_ON_BY` |
| `SUPERSEDES` | Version lineage across artifact identities | SPEC-002 → SPEC-001 | `SUPERSEDED_BY` |
| `GOVERNS` | Policy application | POLICY → any | `GOVERNED_BY` |
| `EVIDENCES` | Assurance relation | EVIDENCE → any | `EVIDENCED_BY` |
| `CONFLICTS_WITH` | Detected contradiction (symmetric) | SPEC ↔ SPEC | itself |

### 4.1 Link origin and confidence

| `origin` | Meaning | Default `status` | Can be `ACCEPTED` without disposition? |
|----------|---------|------------------|----------------------------------------|
| `HUMAN` | Asserted by a principal | `ACCEPTED` | n/a |
| `ANALYZER` | Deterministic derivation (AST, OpenAPI parse, annotation scan) | `ACCEPTED` if `confidence = 1.0` | Yes when confidence is exact |
| `LLM_PROPOSED` | Inferred by a model | `PROPOSED` | **No** |

`confidence ∈ [0,1]`. Analyzer links from `// @spec SPEC-001` annotations have confidence `1.0`;
links inferred from identifier similarity carry the analyzer's computed score and remain `PROPOSED`
below the tenant's `link_auto_accept_threshold` (default 0.95, analyzer-only).

## 5. The five traceability queries — resolution plan

Implemented in `internal/artifactgraph/query`. All are recursive CTEs over
`trace_links` with `(tenant_id, project_id)` as the leading index columns, bounded by a
configurable max depth (default 12) and a visited-set to terminate cycles.

| Question | Traversal |
|----------|-----------|
| What business requirement caused this code? | `CODE --SATISFIES/DERIVED_FROM--> SPEC --SATISFIES--> REQ --DERIVED_FROM--> PRD` (reverse closure, `ACCEPTED` links only) |
| What specifications are affected by this commit? | commit → changed paths → `code_units` by (repo, path, symbol range) → `SATISFIES` → SPEC |
| What code implements this requirement? | `REQ --SATISFIED_BY--> SPEC --SATISFIED_BY/IMPLEMENTED_BY--> CODE` |
| What BPMN represents this specification? | `SPEC --REPRESENTED_BY--> BPMN_PROCESS` (direct typed edge) |
| What deployments are affected by this requirement? | forward closure to `CODE`, then `CODE → PIPELINE_DEF → DEPLOYMENT` joined with active deployment state |

Each query returns the traversed **path**, not just the endpoints, so the UI can render the chain
and the auditor can see the justification for each hop.

## 6. Impact analysis

Impact is computed as a **typed reachability set with decay**:

```
impact(a, v) = { (b, w, reason, distance, severity) }
```

Rules:

- Traversal follows inverse edges from the changed artifact.
- Severity per hop is determined by `link_type` and the *kind* of change:
  - a change to an `APPROVED` `REQUIREMENT` → `HIGH` for all directly satisfying specs;
  - a non-semantic change (formatting, comment) detected by the type-aware differ → `INFO`.
- The type-aware differ is deterministic and per-artifact-type (JSON structural diff for specs, BPMN
  element diff for processes, AST symbol diff for code). No LLM participates in computing impact.
- The LLM is used only to *explain* an already-computed impact set in natural language, and its
  explanation is stored as an annotation, never as an edge.

## 7. Storage model

| Concern | Store | Rationale |
|---------|-------|-----------|
| Artifact metadata, versions, links, status | PostgreSQL | Transactional invariants, RLS isolation, recursive CTEs |
| Artifact content (canonical JSON) | PostgreSQL `JSONB` if < 256 KB, else object storage | Small payloads stay queryable; large payloads (BPMN, source archives) go to S3 |
| Rendered forms & evidence | Object storage, versioned + object-lock | Immutability enforced by the storage layer, not only by application code |
| Graph traversal cache | Redis, key `sf:{tenant}:graph:{project}:{query_hash}` | Invalidated on `artifact.version.created` / `trace_link.changed` |
| Domain events | Kafka-compatible log, key = `tenant_id:aggregate_id` | Per-aggregate ordering, replay for projections |

Content larger than the inline threshold is stored as `content_ref` (a `sha256:` digest plus bucket
key). The digest is verified on read; the platform refuses to serve content whose digest does not
match the recorded `content_hash` inputs.

## 8. Integrity verification

Three independent layers:

1. **Read-path verification.** Every artifact read recomputes the canonical hash and compares.
   Mismatch → `artifact.integrity.violated` event, request fails closed, incident auto-created.
2. **Audit chain.** Artifact seal operations append to the tenant's hash-chained audit log; the
   chain head is anchored to write-once object storage hourly.
3. **Periodic sweep.** A worker re-verifies a rolling sample (default 2%/day, 100%/50 days) of
   sealed versions and all approval evidence digests, publishing `integrity.sweep.completed`.

## 9. Schema evolution

- Envelope schema (`specforge.artifact.v1`) and payload schemas (`specforge.spec.v1`, …) version
  independently. Both are recorded on every version.
- Only additive changes within a major version. A breaking payload change mints `v2` and ships a
  **forward migration function** plus a **reader** for `v1`. Old versions are never rewritten —
  they remain valid under the schema they were sealed with.
- `schemas/` in this repository is the source of truth; the Go types are generated from it, and CI
  fails if generated types drift from the schemas.

## 10. Anti-patterns explicitly forbidden

| Forbidden | Why | Enforcement |
|-----------|-----|-------------|
| Mutating an `APPROVED` version | Destroys evidence | No repository method exists; DB trigger rejects `UPDATE` on sealed rows |
| Storing an LLM response directly as an artifact | Unvalidated authority | `artifact.Create` requires a `content_schema` and validates before write |
| Deriving traceability at query time by string matching | Non-defensible | Links must be rows with origin and confidence |
| Cross-project or cross-tenant links | Isolation breach | DB check constraint + RLS |
| Deleting audit records | Tamper | Table has no `DELETE` grant; append-only trigger |
