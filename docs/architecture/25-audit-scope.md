# SpecForge — Audit Scope & Retention

**Status:** Baseline v1.0
Implements brief §25.

---

## 1. Rule

An operation in the **mandatory** set below cannot commit unless its audit record commits in the same
database transaction. The audit writer participates in the caller's transaction; there is no
"log after commit" path for these operations.

## 2. Mandatory audited operations

| Domain | Actions |
|--------|---------|
| Identity | login (success/failure), logout, step-up, token refresh anomaly, API key create/revoke/first-use, role assignment change, IdP mapping change, break-glass grant/use/expiry |
| Tenancy | tenant create/suspend/reinstate/deprovision/purge-order/purge-complete, settings change (with redacted before/after diff) |
| Project | create, archive, restore, purge |
| Artifact | create, draft update, every FSM transition, **approve**, freeze, supersede, abandon, integrity violation, evidence write |
| Trace links | create, accept, reject, mark stale |
| PRD | discovery start, document ingest, analysis complete, change request, version generate, approve |
| Specifications / models / code | generate, update, approve, schema validation failure |
| Governance | gate request and decision, disposition recorded, exception granted/renewed/expired, waiver, policy publish, DA decision and votes, ADR |
| Synchronization | drift detected, proposal created/accepted/rejected/applied |
| Delivery | pipeline register, trigger, approval step, deployment start/complete/fail/rollback |
| Runtime | incident create/ack/escalate/mitigate/resolve, runtime write actions (rollback, scale) |
| Compliance | scan run, finding suppression, evidence write, export |
| AI | prompt version publish, model binding change, guardrail chain change, inference blocked, policy violation; inference content retained **only** where tenant policy requires |
| Audit | chain verification run and result, anchor write, export |
| Authorization | every DENY; every ALLOW on a sensitive action; sampled ALLOW (1%) on reads; 100% of auditor-role and break-glass activity |

## 3. Record content

Defined in `08-lld.md §6`. Constraints:

- `attributes` is schema-checked per action type and passes through the redactor: no secrets, no raw
  artifact content, no unredacted PII. Content is referenced by hash, never embedded.
- `actor` records the acting principal **and** `on_behalf_of` for delegated system actions.
- `target` records the resource type, ID and version.
- Failures and denials are recorded with the same rigour as successes — an audit trail that only
  contains successes is not an audit trail.

## 4. Tamper evidence

Three layers, each independent:

1. **Hash chain** per tenant: `record_hash = SHA-256(prev_hash ‖ JCS(record − record_hash))`, with a
   gapless per-tenant `sequence` allocated under row lock inside the caller's transaction.
2. **Append-only enforcement**: no `UPDATE`/`DELETE` grant for the application role, plus a trigger
   that raises regardless of grants.
3. **Anchoring**: hourly, the chain head is written to object storage under object-lock (compliance
   mode) via a distinct IAM path, and mirrored to the customer's SIEM. An attacker with full database
   access can therefore corrupt the chain but cannot make the corruption invisible.

Verification: `specforge-cli verify-audit` recomputes the chain between two anchors and reports the
exact sequence at which it diverges. Verification runs nightly and on demand, and its result is
itself audited.

## 5. Retention

| Class | Default retention | Notes |
|-------|------------------|-------|
| Approval evidence and its audit records | 7 years (tenant-configurable, minimum 7 y) | Object-lock enforced; survives tenant purge as a documented legal-basis exception |
| Governance dispositions, exceptions, DA decisions | 7 years | |
| General audit records | 2 years hot, 7 years cold (detached partitions) | Partition detach, never drop under legal hold |
| Pipeline/runtime telemetry-derived audit | 1 year | |
| AI inference records (metadata) | 2 years | Content retention per tenant policy: `none` (default), `hashes_only`, `redacted`, `full` |
| Authorization ALLOW samples | 90 days | Denials follow general audit retention |

## 6. Access and export

- `audit:read` is required to read; `audit:export` to export. Auditor role has both, and its own
  activity is fully audited.
- Export produces a signed NDJSON bundle plus a manifest of content hashes and the anchor references
  needed for offline verification.
- Export is asynchronous, rate-limited, and raises an anomaly alert on unusual volume.
- Platform administrators cannot read tenant audit records without break-glass, which is itself
  audited and disclosed to the tenant.
