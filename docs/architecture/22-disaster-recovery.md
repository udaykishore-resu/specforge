# SpecForge — Disaster Recovery & Business Continuity

**Status:** Baseline v1.0

---

## 1. Objectives

| Class | Data | RPO | RTO | Rationale |
|-------|------|-----|-----|-----------|
| Tier 0 | Approval evidence, audit anchors (object-lock WORM) | **0** | 1 h | Regulatory evidence; cross-region replicated, immutable |
| Tier 1 | PostgreSQL control plane (artifacts, links, governance, audit) | 15 min | 4 h | PITR + cross-region replica |
| Tier 2 | Object storage content (artifact bodies, reports, source archives) | 15 min | 4 h | Versioned + CRR |
| Tier 3 | Event log | 1 h | 8 h | Rebuildable from the outbox and the DB |
| Tier 4 | Redis cache, projections, closure table | ∞ (loss acceptable) | 30 min | Fully derivable; cold-start degrades latency only |

## 2. What makes recovery tractable

The system is designed so that **only two things are irreplaceable**: the PostgreSQL primary and the
WORM evidence bucket. Everything else is derivable:

- Projections (closure table, consistency scores, correlation views) rebuild from the DB + event log.
- The event log itself can be re-emitted from `outbox_events` history for the retention window.
- Caches are pure derivations.
- Artifact content has a `content_hash`; a restored body that does not match its hash is rejected
  rather than silently trusted — so a partial restore is detectable, not corrupting.

## 3. Backup strategy

| Store | Method | Frequency | Retention | Encryption |
|-------|--------|-----------|-----------|-----------|
| PostgreSQL | Automated snapshots + continuous WAL archiving (PITR) | Snapshot daily; WAL continuous (≤ 5 min segments) | 35 d PITR, monthly snapshots 7 y | CMK |
| PostgreSQL | Logical dump per tenant (for tenant-level restore/export) | Weekly | 90 d | CMK |
| Object storage | Versioning + Cross-Region Replication; object-lock on evidence | Continuous | Per tenant retention (default 7 y) | SSE-KMS |
| Secrets | Secret store native replication | Continuous | 90 d version history | KMS |
| Kafka | Topic replication RF=3; critical topics mirrored cross-region | Continuous | Per topic | At rest + TLS |
| IaC & config | Git (the source of truth) + tagged releases | Per commit | ∞ | — |

Backups are **restore-tested quarterly**, and the restore test is itself an evidence-producing
governance activity (`COMPLIANCE_GATE` requires a passing DR validation within the last 90 days).

## 4. Failure scenarios and responses

| # | Scenario | Detection | Response | Target |
|---|----------|-----------|----------|--------|
| 1 | Single pod failure | Probe failure | Kubernetes restarts; PDB keeps capacity | Seconds, no data loss |
| 2 | Node failure | Node NotReady | Rescheduling; topology spread maintains AZ coverage | < 5 min |
| 3 | AZ failure | Multi-AZ health | Multi-AZ RDS failover; stateless tiers already spread | < 15 min, RPO 0 |
| 4 | Database primary failure | RDS event/health | Automatic failover to standby; app reconnects via pooler with retry+backoff | < 15 min, RPO 0 |
| 5 | Database corruption | Integrity sweep / query errors | PITR restore to just before corruption; replay outbox; re-verify content hashes | RTO 4 h, RPO ≤ 15 min |
| 6 | Region failure | Multi-region health checks | Promote cross-region replica, repoint DNS, restore from CRR buckets, rebuild projections | RTO 4 h, RPO ≤ 15 min |
| 7 | Object storage object loss | Hash verification failure on read; integrity sweep | Restore prior version / CRR copy; if evidence, retrieve the object-lock copy | RTO 1 h, RPO 0 for Tier 0 |
| 8 | Event log loss | Consumer lag / broker health | Rebuild topics; re-publish from `outbox_events`; consumers re-process idempotently | RTO 8 h |
| 9 | Cache loss | Redis health | Cold start; degraded latency only | < 30 min |
| 10 | Accidental tenant deletion | `tenant.purge.*` audit | Purge requires dual approval + legal-hold check; before purge, an export bundle exists; restore from the bundle + PITR | RTO 8 h |
| 11 | Ransomware / malicious deletion | Anomaly + integrity alerts | Object-lock prevents evidence deletion; PITR restores DB; immutable audit reconstructs the timeline | RTO 8 h |
| 12 | Compromised credentials | Security alerts | Rotate all secrets, revoke sessions and API keys, force re-auth, audit review, incident process | Immediate containment |
| 13 | LLM provider outage | Circuit breaker | Fallback model chain; if all fail, AI features queue and the rest of the platform continues | Degraded, not down |
| 14 | Guardrail outage | Health/circuit | `fail_closed` blocks AI operations; non-AI platform unaffected | Degraded by design |

## 5. Recovery procedures (summary; full steps in `docs/runbooks/dr/`)

### 5.1 Database PITR restore

1. Declare an incident; freeze writes (scale API to 0 or enable maintenance mode).
2. Identify the target timestamp from the audit trail and the integrity sweep.
3. Restore to a new instance at the target time.
4. Run `specforge-migrate status` to confirm schema version alignment with the deployed image.
5. Run `specforge-cli verify-audit --all-tenants` — the chain must verify to the restore point.
6. Run `specforge-cli verify-content --sample=100%` for artifacts sealed in the last 24 h.
7. Repoint the application, scale up, re-enable writes.
8. Replay unpublished outbox rows (the relay does this automatically).
9. Rebuild projections (`specforge-cli rebuild-projections`).
10. Record a disposition documenting data loss (if any) with the affected artifact list.

### 5.2 Region failover

1. Confirm the primary region is unrecoverable within RTO.
2. Promote the cross-region PostgreSQL replica.
3. Confirm CRR completion status for content and evidence buckets; list any objects not yet
   replicated (these define actual data loss).
4. Deploy the platform in the DR region from the tagged release (IaC is region-parameterized).
5. Update DNS/CDN origin; verify with the smoke journey.
6. Rebuild projections; verify audit chains.
7. Notify tenants with the measured RPO and the specific affected artifacts.

### 5.3 Evidence integrity recovery

If a sealed artifact's body fails hash verification:

1. The read fails closed (`INTEGRITY_VIOLATION`) — the platform never serves an unverified body.
2. `artifact.integrity.violated` raises a CRITICAL incident automatically.
3. Retrieve the object-lock version from the evidence bucket and re-verify.
4. If the WORM copy verifies, restore it and record a disposition.
5. If it does not, the artifact is quarantined, its dependents are flagged, and the governance case
   escalates to the Design Authority. The approval is **not** silently re-issued.

## 6. Continuity of governance

DR is not only about uptime — the assurance record must survive too:

- Audit anchors are written to a bucket with object-lock in **compliance mode**, using a distinct
  IAM path from the application, so even a full application-plane compromise cannot remove them.
- The audit stream is mirrored to the customer's SIEM, giving an independent copy outside SpecForge.
- Approval evidence is content-addressed; a tenant can verify any approval offline with
  `specforge-cli verify-evidence --bundle export.tar.zst`, which recomputes hashes and validates the
  chain without contacting the platform. This is what makes the evidence defensible even in a
  scenario where SpecForge itself is unavailable or distrusted.

## 7. Testing and validation

| Test | Frequency | Evidence produced |
|------|-----------|-------------------|
| Restore drill (PITR to a scratch environment + full verification) | Quarterly | Restore time, integrity report |
| Region failover game day | Annually | Measured RTO/RPO, gaps list |
| Backup integrity check (automated restore + smoke) | Weekly | Pass/fail evidence artifact |
| Chaos: kill pods, sever DB, slow guardrails, drop broker | Per release | Resilience report |
| Offline evidence verification | Per release | CLI verification of a sample bundle |

A failed or overdue DR validation blocks the `COMPLIANCE_GATE`, which blocks production deployment.
DR is therefore not a document — it is a gate.
