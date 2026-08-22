# SpecForge — Multi-Tenancy Architecture

**Status:** Baseline v1.0

---

## 1. Isolation modes

| Mode | Database | Object storage | Cache | Events | Keys | Compute |
|------|----------|---------------|-------|--------|------|---------|
| `shared` | Shared cluster, shared schema, **RLS** | Shared bucket, per-tenant key prefix | Shared Redis, `sf:{tenant}:` namespace | Shared topics, tenant in key+envelope | Platform CMK + per-tenant data key | Shared pods |
| `dedicated_schema` | Shared cluster, **schema per tenant**, RLS | Bucket per tenant | Shared Redis, namespace + separate logical DB | Shared topics | Per-tenant CMK | Shared pods |
| `single_tenant` | Dedicated cluster | Dedicated buckets | Dedicated Redis | Dedicated cluster/topics | Customer-managed CMK | Dedicated namespace/cluster |

The application code is identical across modes. Mode is a tenant attribute; routing is resolved by
the storage/DB/event adapters. **RLS is always on**, so the isolation path is exercised in every
deployment, including single-tenant — an untested security control is not a control.

## 2. Tenant boundaries (brief §18)

| Boundary | Mechanism | Failure behaviour |
|----------|-----------|-------------------|
| Database | `tenant_id` first column of every PK/index + `FORCE ROW LEVEL SECURITY` with `current_setting('app.tenant_id')`; app role is not the table owner and lacks `BYPASSRLS` | Query without tenant context returns 0 rows |
| Object storage | Key prefix `{{tenant_id}}/{{project_id}}/…`; IAM/bucket policy conditions on the prefix; per-tenant CMK in dedicated modes | `AccessDenied` |
| Cache | Namespace `sf:{tenant_id}:…` injected server-side from `TenantContext`; a client-supplied key fragment is escaped and cannot contain `:` | Cache miss, never a cross-read |
| Events | Partition key `tenant_id:aggregate_id`; envelope carries `tenant_id`; consumers open a tenant-scoped session before handling and reject envelopes whose tenant is not resolvable | Message → DLQ |
| Secrets | Path `sf/{env}/{tenant_id}/…`; workload IAM scoped by path | `AccessDenied` |
| Authorization | Tenant match is the first predicate of every decision (`05-authorization-model.md §2`) | 403 + audit |
| Artifacts | Artifact IDs are project-scoped; a cross-project link is rejected by a `CHECK` constraint | 400 |
| AI configuration | Model bindings, prompt versions, guardrail chains, provider allowlists and quotas are tenant attributes | Falls back to platform defaults only if the tenant permits |
| Audit | Per-tenant hash chain and per-tenant sequence; export is tenant-scoped | — |

## 3. Tenant context propagation

```
Edge → token claim (tenant) ⨯ host/subdomain ⨯ path segment  →  must all agree
      → TenantContext in context.Context
      → db.Tx sets app.tenant_id (SET LOCAL, transaction-scoped)
      → objstore prefix, cache namespace, event key, secret path all derive from it
      → outgoing events carry it; consumers rebuild TenantContext from the envelope
```

Rules that make this safe:

1. **Never** derive tenant from a request body field.
2. **Never** carry tenant context across an async boundary implicitly — it travels in the event
   envelope and is re-established explicitly by the consumer.
3. `SET LOCAL` (not `SET`) so a pooled connection cannot leak context to the next borrower.
4. A background job without an explicit tenant is a **platform** job and may only touch
   platform-scoped tables; the type system separates `PlatformDB` from `TenantDB`.

## 4. Per-tenant configuration surface

```yaml
tenant:
  isolation_mode: shared
  region: eu-west-1
  data_residency: EU
  settings:
    four_eyes: true
    architect_can_approve_prd: false
    step_up_max_age: 15m
    evidence_retention: 7y
    link_auto_accept_threshold: 0.95
    max_proposals_per_sweep: 50
  ai:
    allowed_providers: [simulator, anthropic]
    default_model_binding: MB-reasoning@v3
    guardrail_chain: GRC-strict@v2
    pii_redaction: required
    provider_data_retention: none
    monthly_token_budget: 50_000_000
  policy_set: POL-SET@v9
  integrations:
    vcs:   { provider: github, org: acme, app_installation_id: "…" }
    ci:    { provider: github_actions }
    idp:   { issuer: "…", tenant_claim: "…", group_mapping_version: 4 }
    notify:{ slack_workspace: "…", pagerduty_service: "…" }
  environments: [dev, staging, prod]
  quotas: { rps: 200, concurrent_jobs: 10, storage_gb: 500 }
```

Changes emit `tenant.settings.updated`, invalidate the policy and permission caches, and are audited
with a before/after diff of the changed keys (values redacted where sensitive).

## 5. Noisy-neighbour control

| Resource | Control |
|----------|---------|
| API | Per-tenant token bucket (plan-based), per-principal sub-bucket, `429` + `Retry-After` |
| Inference | Per-tenant tokens/minute and monthly budget; the gateway rejects with `quota.tokens_exhausted` and emits a budget event at 80/95/100% |
| Long jobs | Per-tenant concurrency lease cap; queued beyond it, with a visible queue position |
| Database | `statement_timeout` per request class; heavy graph queries routed to read replicas; per-tenant connection share via a weighted semaphore |
| Event log | Per-tenant produce quota; a tenant flooding events is throttled, not the cluster |
| Storage | Quota with soft (warn) and hard (block writes) thresholds |

## 6. Provisioning and deprovisioning

**Provision** (driven by `tenant.created`, idempotent, resumable):
1. Allocate tenant record (`PROVISIONING`).
2. Create storage prefixes/buckets, apply bucket policy + object-lock on evidence.
3. Create KMS data key (or CMK in dedicated modes).
4. Create secret store path and scoped IAM policy.
5. Create schema (dedicated mode) and run migrations.
6. Seed: audit sequence row, default policy set, default role mappings, default guardrail chain.
7. Register topics/quotas.
8. Transition to `ACTIVE`; emit `tenant.provisioned`.

Failure at any step leaves the tenant in `PROVISIONING` with a recorded reason; the job retries with
backoff. No partial tenant is ever `ACTIVE`.

**Deprovision → purge**:
1. `DEPROVISIONING`: writes blocked, reads allowed for export.
2. Export bundle generated (artifacts, evidence, audit) and delivered.
3. `TenantPurgeOrder` requires two approvers (`platform_admin` + `compliance`) and passes an
   automated **legal-hold check** that fails closed.
4. Purge: object versions deleted except those under object-lock retention (documented as a
   retained-evidence exception), DB rows removed, keys scheduled for destruction, topics deleted.
5. `tenant.purge.completed` with a purge certificate stored in platform-scoped WORM storage.

## 7. Cross-tenant features — and their guards

Some platform features are inherently cross-tenant. Each is explicitly designed so that no tenant
data crosses:

| Feature | Guard |
|---------|-------|
| Platform-wide metrics/dashboards | Aggregated counts only; no artifact content; k-anonymity threshold before display |
| Shared prompt templates | Platform-owned templates are content-only, contain no tenant data, and are copied (versioned) into the tenant on adoption |
| Model bindings | Configuration only |
| Vulnerability feeds | External data pushed to tenants; no tenant data leaves |
| Support/break-glass | §`11-security-architecture.md`; time-boxed, dual-approved, audited, tenant-notified |

There is **no** cross-tenant search, no shared vector index, and no cross-tenant model
fine-tuning or caching of inference results.

## 8. Testing tenant isolation

The isolation suite (`test/isolation`) runs on every release:

1. Create tenants A and B with content in each.
2. For every API route, call it with A's credentials against B's resource IDs → expect 403/404,
   never 200, and assert zero rows returned at the DB layer.
3. Attempt a forged tenant claim → expect 403 and a `security.tenant_mismatch` audit record.
4. Attempt a repository query with no tenant context → expect an error, not an unscoped result.
5. Attempt to read B's object keys with A's storage credentials → expect `AccessDenied`.
6. Attempt to construct a cache key outside A's namespace → assert impossible by API shape.
7. Publish an event with a mismatched tenant → assert the consumer rejects it to the DLQ.
8. Cross-project link creation → assert `CHECK` violation.

A failure in this suite is a release blocker with no exception path.
