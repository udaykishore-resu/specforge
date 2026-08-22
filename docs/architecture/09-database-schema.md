# SpecForge — Database Schema

**Status:** Baseline v1.0
**Source of truth:** `migrations/*.sql` (forward-only). This document explains the design.

---

## 1. Conventions

- PostgreSQL 16. UUIDv7 primary keys (`id`), generated application-side for time-ordering.
- Every tenant-scoped table has `tenant_id uuid NOT NULL` as the **first** column of its primary
  index, and `FORCE ROW LEVEL SECURITY`.
- Timestamps are `timestamptz`, always UTC. `created_at`/`updated_at` on mutable tables.
- Optimistic concurrency via `version_no bigint NOT NULL DEFAULT 1`.
- Soft delete via status enums, never a `deleted` boolean.
- No `ON DELETE CASCADE` on artifact/audit data — deletion is a governed purge operation.
- Enum-like columns are `text` with `CHECK` constraints, not PG enums (cheap evolution, and the
  constraint is visible in the schema).

## 2. Row-Level Security

```sql
ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;
ALTER TABLE <t> FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON <t>
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
```

`FORCE` matters: without it the table owner bypasses RLS, and the application role is often the
owner in simple deployments. The migration runner runs as a separate `sf_migrator` role;
the application connects as `sf_app`, which is **not** the table owner and has no `BYPASSRLS`.

`current_setting('app.tenant_id', true)` returns NULL when unset, so a query without tenant context
matches nothing rather than everything.

## 3. Entity relationship overview

```mermaid
erDiagram
    TENANTS ||--o{ PROJECTS : owns
    TENANTS ||--o{ PRINCIPALS : has
    TENANTS ||--o{ ROLE_ASSIGNMENTS : scopes
    TENANTS ||--o{ AUDIT_RECORDS : chains
    PROJECTS ||--o{ ARTIFACTS : contains
    ARTIFACTS ||--o{ ARTIFACT_VERSIONS : versions
    ARTIFACT_VERSIONS ||--o{ TRACE_LINKS : from
    ARTIFACT_VERSIONS ||--o{ TRACE_LINKS : to
    ARTIFACT_VERSIONS ||--o{ EVIDENCE : substantiates
    PROJECTS ||--o{ GOVERNANCE_CASES : adjudicates
    GOVERNANCE_CASES ||--|| DISPOSITIONS : concludes
    GOVERNANCE_CASES ||--o{ GATE_EVALUATIONS : contains
    PROJECTS ||--o{ DRIFT_FINDINGS : detects
    DRIFT_FINDINGS ||--o{ CHANGE_PROPOSALS : motivates
    PROJECTS ||--o{ PIPELINES : defines
    PIPELINES ||--o{ PIPELINE_RUNS : executes
    PIPELINE_RUNS ||--o{ DEPLOYMENTS : produces
    DEPLOYMENTS ||--o{ INCIDENTS : may_cause
    TENANTS ||--o{ INFERENCE_RECORDS : meters
    TENANTS ||--o{ OUTBOX_EVENTS : emits
```

## 4. Phase 1 tables (implemented)

### 4.1 `tenants`

Platform-scoped (no RLS; access controlled by permission and by explicit `tenant_id` filters).

| Column | Type | Notes |
|--------|------|-------|
| `id` | uuid PK | UUIDv7 |
| `slug` | text UNIQUE | immutable, `^[a-z][a-z0-9-]{2,39}$` |
| `name` | text | |
| `status` | text CHECK | PROVISIONING/ACTIVE/SUSPENDED/DEPROVISIONING/PURGED/FAILED |
| `isolation_mode` | text CHECK | shared/dedicated_schema/single_tenant |
| `region` | text | |
| `settings` | jsonb | validated against `schemas/tenant_settings.v1.json` |
| `created_by`,`created_at`,`updated_at`,`version_no` | | |

### 4.2 `projects`

PK `(tenant_id, id)`; unique `(tenant_id, key)`. `key` is the artifact ID namespace (`^[A-Z][A-Z0-9]{1,9}$`).
`pdlc_phase` tracks the AI-PDLC state. RLS on.

### 4.3 `principals`, `role_assignments`, `api_keys`, `idp_role_mappings`

- `principals`: unique `(issuer, subject)`; `kind ∈ USER|SERVICE_ACCOUNT|SYSTEM`; `status`.
- `role_assignments`: `(tenant_id, principal_id, project_id NULLS NOT DISTINCT, role)` unique;
  `expires_at` optional; `granted_by`, `granted_at`.
  Partial index on `expires_at` for the expiry sweeper.
- `api_keys`: `key_id` unique, `secret_hash` (argon2id), `permissions text[]`, `expires_at`,
  `revoked_at`, `last_used_at`. A `CHECK` forbids approval permissions on service accounts.
- `idp_role_mappings`: versioned `(tenant_id, idp_group, role, mapping_version)`.

### 4.4 `artifacts` / `artifact_versions` / `trace_links`

```sql
CREATE TABLE artifacts (
  tenant_id uuid NOT NULL, project_id uuid NOT NULL,
  artifact_id text NOT NULL,            -- 'SPEC-AUTH-001'
  artifact_type text NOT NULL CHECK (artifact_type IN (...)),
  current_version int NOT NULL DEFAULT 0,
  status text NOT NULL,
  labels jsonb NOT NULL DEFAULT '{}',
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(), version_no bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, project_id, artifact_id)
);

CREATE TABLE artifact_versions (
  tenant_id uuid NOT NULL, project_id uuid NOT NULL,
  artifact_id text NOT NULL, version int NOT NULL CHECK (version >= 1),
  artifact_type text NOT NULL,
  status text NOT NULL CHECK (status IN
    ('DRAFT','AI_REVIEW','USER_REVIEW','CHANGES_REQUESTED','APPROVED','FROZEN','SUPERSEDED','ABANDONED')),
  content_schema text NOT NULL,
  content jsonb,                          -- inline when small
  content_ref text,                       -- 'sha256:…' when externalized
  content_hash text NOT NULL,
  parent_artifact_id text, parent_artifact_version int,
  source_artifact_id text, source_artifact_version int,
  previous_version int,
  change_summary text NOT NULL DEFAULT '',
  generator jsonb NOT NULL DEFAULT '{}',
  created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  approved_by uuid, approved_at timestamptz,
  approval_comment text, approval_evidence jsonb,
  sealed_at timestamptz,
  version_no bigint NOT NULL DEFAULT 1,
  PRIMARY KEY (tenant_id, project_id, artifact_id, version),
  CONSTRAINT content_present CHECK (content IS NOT NULL OR content_ref IS NOT NULL),
  CONSTRAINT approved_requires_evidence CHECK (
    status <> 'APPROVED' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL
      AND approval_evidence IS NOT NULL AND coalesce(approval_comment,'') <> '')),
  CONSTRAINT chain_start CHECK ((version = 1) = (previous_version IS NULL)),
  CONSTRAINT chain_step  CHECK (previous_version IS NULL OR previous_version = version - 1)
);
```

**Immutability trigger** — the structural guarantee behind "never overwrite approved PRDs":

```sql
CREATE FUNCTION enforce_version_immutability() RETURNS trigger AS $$
BEGIN
  IF OLD.status IN ('APPROVED','FROZEN','SUPERSEDED','ABANDONED') THEN
     -- only status may change, and only along the legal terminal transitions
     IF (to_jsonb(NEW) - 'status' - 'version_no' - 'updated_at')
        IS DISTINCT FROM (to_jsonb(OLD) - 'status' - 'version_no' - 'updated_at') THEN
        RAISE EXCEPTION 'artifact_version % v% is sealed (status %)', OLD.artifact_id, OLD.version, OLD.status
          USING ERRCODE = 'integrity_constraint_violation';
     END IF;
     IF NOT (OLD.status, NEW.status) IN
        (('APPROVED','FROZEN'),('APPROVED','SUPERSEDED'),('FROZEN','SUPERSEDED')) THEN
        RAISE EXCEPTION 'illegal transition % -> % on sealed version', OLD.status, NEW.status
          USING ERRCODE = 'integrity_constraint_violation';
     END IF;
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
```

Only one `APPROVED` version per artifact:

```sql
CREATE UNIQUE INDEX one_approved_per_artifact
  ON artifact_versions (tenant_id, project_id, artifact_id)
  WHERE status = 'APPROVED';
```

`trace_links`:

```sql
CREATE TABLE trace_links (
  tenant_id uuid NOT NULL, project_id uuid NOT NULL, link_id uuid NOT NULL,
  from_artifact_id text NOT NULL, from_version int NOT NULL,
  to_artifact_id   text NOT NULL, to_version   int NOT NULL,
  link_type text NOT NULL CHECK (link_type IN (...)),
  origin text NOT NULL CHECK (origin IN ('HUMAN','ANALYZER','LLM_PROPOSED')),
  confidence numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  status text NOT NULL CHECK (status IN ('PROPOSED','ACCEPTED','REJECTED','STALE')),
  evidence jsonb, created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  disposition_id uuid,
  PRIMARY KEY (tenant_id, project_id, link_id),
  CONSTRAINT no_self_link CHECK (from_artifact_id <> to_artifact_id OR from_version <> to_version),
  CONSTRAINT llm_needs_disposition CHECK (status <> 'ACCEPTED' OR origin <> 'LLM_PROPOSED' OR disposition_id IS NOT NULL)
);
CREATE UNIQUE INDEX trace_links_unique ON trace_links
  (tenant_id, project_id, from_artifact_id, from_version, to_artifact_id, to_version, link_type);
CREATE INDEX trace_links_forward  ON trace_links (tenant_id, project_id, from_artifact_id, link_type) WHERE status='ACCEPTED';
CREATE INDEX trace_links_backward ON trace_links (tenant_id, project_id, to_artifact_id,   link_type) WHERE status='ACCEPTED';
```

The `llm_needs_disposition` check is the database-level expression of "AI proposes, governance
approves" — an LLM-originated link literally cannot be `ACCEPTED` without a disposition row.

### 4.5 `audit_records`

```sql
CREATE TABLE audit_records (
  tenant_id uuid NOT NULL, sequence bigint NOT NULL,
  id uuid NOT NULL, project_id uuid,
  action text NOT NULL, outcome text NOT NULL CHECK (outcome IN ('SUCCESS','DENIED','FAILURE')),
  severity text NOT NULL,
  actor jsonb NOT NULL, target jsonb NOT NULL, attributes jsonb NOT NULL DEFAULT '{}',
  request_id text, trace_id text,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  prev_hash text NOT NULL, record_hash text NOT NULL,
  PRIMARY KEY (tenant_id, sequence)
);
CREATE TABLE audit_sequences (tenant_id uuid PRIMARY KEY, next_sequence bigint NOT NULL DEFAULT 1,
                              head_hash text NOT NULL DEFAULT repeat('0',64));
CREATE TABLE audit_anchors (tenant_id uuid, anchored_at timestamptz, sequence bigint,
                            head_hash text, storage_ref text, PRIMARY KEY (tenant_id, anchored_at));
```

Grants: `GRANT SELECT, INSERT ON audit_records TO sf_app;` — no `UPDATE`, no `DELETE`. A
`BEFORE UPDATE OR DELETE` trigger raises regardless of grants, protecting against a mis-granted role.

Partitioned by month (`RANGE (occurred_at)`) with per-tenant local indexes; old partitions are
detached to cold storage after the retention period, never dropped while under legal hold.

### 4.6 `outbox_events`

```sql
CREATE TABLE outbox_events (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, project_id uuid,
  event_type text NOT NULL, schema text NOT NULL, schema_version int NOT NULL,
  aggregate_type text NOT NULL, aggregate_id text NOT NULL, aggregate_version int,
  partition_key text NOT NULL, payload jsonb NOT NULL, payload_hash text NOT NULL,
  correlation jsonb NOT NULL, actor jsonb NOT NULL,
  occurred_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz, attempts int NOT NULL DEFAULT 0, last_error text
);
CREATE INDEX outbox_unpublished ON outbox_events (created_at) WHERE published_at IS NULL;
```

### 4.7 `idempotency_keys`, `processed_events`

`idempotency_keys(tenant_id, key)` → `request_hash`, `status`, `response_body`, `expires_at`.
`processed_events(consumer_group, event_id)` → `processed_at`, with a TTL sweeper.

## 5. Phases 2–12 tables (specified, migrations staged)

| Table | Purpose |
|-------|---------|
| `prd_discovery_sessions`, `prd_conversation_turns`, `prd_change_requests`, `ingested_documents` | PRD Studio |
| `requirements`, `specifications`, `acceptance_criteria`, `business_rules` | Spec Engine (projections over artifacts for query ergonomics) |
| `graph_closure` | Materialized transitive closure `(from, to, link_path, distance)` refreshed by projection |
| `governance_cases`, `gate_evaluations`, `policy_results`, `dispositions`, `exceptions`, `compensating_controls`, `policy_sets` | Governance |
| `drift_findings`, `change_proposals`, `impact_analyses`, `consistency_scores` | Synchronization |
| `repositories`, `code_units`, `code_annotations`, `ast_index` | Reverse engineering + traceability |
| `pipelines`, `pipeline_runs`, `pipeline_stages`, `pipeline_jobs`, `failure_analyses` | Delivery |
| `deployments`, `workloads`, `pods`, `runtime_events`, `incidents`, `incident_timeline`, `escalation_policies` | Runtime |
| `scans`, `findings`, `sboms`, `evidence` | Compliance |
| `prompt_templates`, `model_bindings`, `guardrail_chains`, `inference_records`, `ai_usage_ledger` | AI platform |

## 6. Indexing strategy

| Query | Index |
|-------|-------|
| Artifact by ID | PK `(tenant_id, project_id, artifact_id)` |
| Latest version | `(tenant_id, project_id, artifact_id, version DESC)` |
| Approved version | partial unique index (§4.4) |
| Forward/backward traversal | partial indexes on `status='ACCEPTED'` (§4.4) |
| Audit by actor/action/time | `(tenant_id, occurred_at DESC)`, `(tenant_id, action, occurred_at DESC)`, GIN on `actor` |
| Outbox relay | partial index on `published_at IS NULL` |
| Findings triage | `(tenant_id, project_id, severity, status, detected_at DESC)` |
| Full-text over PRD/spec content | GIN on `to_tsvector('english', content->>'body')`, per-tenant |

## 7. Performance notes

- Recursive CTEs are bounded (`WHERE depth < $max`) and use the partial `ACCEPTED` indexes; measured
  target p95 < 500 ms at 10^6 links per tenant. Above that, the `graph_closure` projection serves
  the query and the CTE becomes the fallback/verification path.
- `content jsonb` is inlined below 256 KB; larger payloads go to object storage so TOAST churn does
  not dominate. A `CHECK (pg_column_size(content) < 262144)` enforces the threshold.
- Connection pooling: pgx pool, `max_conns = 25` per API replica; PgBouncer in transaction mode is
  **not** used in front of the app because `SET LOCAL` RLS settings require session/transaction
  affinity — the app pool is the pool.
- Read replicas serve projections and graph reads with `max_staleness = 5s`; all writes and all
  sealing reads go to the primary.

## 8. Migrations

Forward-only, numbered, applied by `specforge-migrate` with an advisory lock so concurrent pods
cannot race. Every migration is reviewed for: RLS enablement on new tenant tables, index coverage,
lock duration (`CREATE INDEX CONCURRENTLY` for large tables, in its own migration), and rollback
plan documented in the file header. Down-migrations are not shipped; recovery is restore-plus-replay.
