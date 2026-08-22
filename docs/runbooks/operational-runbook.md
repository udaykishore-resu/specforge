# SpecForge — Operational Runbook

**Audience:** SRE / DevOps on call.
**Rule:** every alert in `18-observability-architecture.md §8` has a section here. An alert without a
runbook section fails the alert-rule lint in CI.

---

## 0. First five minutes

1. Check the platform health dashboard: error rate, latency, saturation, dependency health.
2. Check `/readyz` on each service — it reports per-dependency status, so a failing dependency is
   named, not guessed.
3. Check recent deployments (`sf_deployments_total`, rollout history). Most incidents follow a change.
4. Check `sf_outbox_age_seconds` and consumer lag — a stalled event path degrades many features at
   once and looks like several unrelated problems.
5. If the incident is security- or integrity-related, page Security **first** and preserve state:
   do not restart pods, do not truncate logs, snapshot the database.

## 1. Integrity violation (CRITICAL)

**Alert:** `sf_integrity_violations_total` increased / `artifact.integrity.violated`.

This means a stored artifact body no longer matches its recorded hash.

1. Do **not** restart or redeploy. Preserve state.
2. Identify the artifact: the event payload carries `artifact_id`, `version`, `expected_hash`,
   `actual_hash`, `detector`.
3. Confirm scope: `specforge-cli verify-content --tenant <t> --since 30d` to see whether it is
   isolated or systemic.
4. Verify the audit chain: `specforge-cli verify-audit --tenant <t>`. A chain failure alongside a
   content failure indicates tampering rather than corruption.
5. Retrieve the WORM copy from the evidence bucket and verify it (`22-disaster-recovery.md §5.3`).
6. Page Security. Open a CRITICAL incident. Notify the tenant's security contact.
7. Quarantine: the platform already fails reads closed. Flag dependent artifacts.
8. Record a disposition once resolved; the artifact is only re-instated from a verified WORM copy.

## 2. Audit chain verification failure (CRITICAL)

**Alert:** `audit.chain.verification.failed`.

1. Preserve state; snapshot the database immediately.
2. Run `specforge-cli verify-audit --tenant <t> --verbose` to get the exact failing sequence.
3. Compare against the last hourly anchor in the WORM bucket — the anchor establishes the last
   known-good chain head and therefore the tampering window.
4. Compare against the SIEM mirror of `sf.audit.v1` for the same range.
5. Page Security; treat as a potential insider or compromise event; do not attempt to "repair" the
   chain — the break itself is the evidence.
6. Follow the security incident process; the affected range is disclosed to the tenant.

## 3. API error budget burn / elevated 5xx

1. Identify the failing route(s) from `sf_http_requests_total{status=~"5.."}`.
2. Check dependency health (`/readyz`, DB pool saturation, Redis, broker, object store).
3. Check recent deploys — if correlated, roll back first and diagnose after
   (`deployment:rollback`, or `helm rollback specforge <rev>`).
4. If DB-driven: check `sf_db_pool_connections{state="waiting"}`, slow query log, locks
   (`pg_stat_activity` with `wait_event_type='Lock'`), and whether a migration is running.
5. If a single tenant is driving load, apply a temporary quota (`tenant.quotas.rps`) and inform them.
6. If shedding is needed, low-priority AI purposes shed first — this is automatic above the SLO, but
   can be forced with `SF_LOAD_SHED=aggressive`.

## 4. Outbox lag / consumer lag

**Symptoms:** events delayed, projections stale, notifications missing, drift not detected.

1. `sf_outbox_pending` rising + `sf_outbox_age_seconds` > 60 s → the relay is stuck or the broker is
   unhealthy.
2. Check relay pod logs for publish errors; check broker health and ACLs.
3. Writes still succeed while the outbox backs up — this is by design. Do not disable the outbox.
4. If the broker is down: fix the broker; the relay drains automatically. Confirm drain rate.
5. If a single consumer group lags: check its DLQ; a poison message circuit-breaks one partition
   rather than the group. Inspect `sf.dlq.v1`, fix, and replay with
   `specforge-cli dlq replay --group <g> --since <t>` (each replay is audited).
6. Never delete outbox rows to "clear" a backlog — that destroys the event record.

## 5. Database issues

| Symptom | Action |
|---------|--------|
| Connection exhaustion | Check `max_conns` vs. replicas; look for a leaked transaction (`idle in transaction`); the app sets `idle_in_transaction_session_timeout`, so a leak indicates a bypass |
| Lock contention | Identify blocking PIDs; long-running sealing transactions are the usual cause; consider whether a migration is holding a lock |
| Replication lag | Graph/projection reads use replicas with a staleness bound; if lag exceeds it, reads fall back to the primary — expect latency, not incorrectness |
| Migration stuck | The runner holds an advisory lock; check `pg_locks`; never kill mid-DDL — wait or restore |
| Disk pressure | Check audit partitions and `outbox_events` retention; detach old audit partitions to cold storage (never drop under legal hold) |

## 6. AI gateway / guardrails

| Symptom | Action |
|---------|--------|
| `guardrail.circuit_opened` | Check the guardrail container's health and resources; `fail_closed` guardrails block AI features while open — this is correct. Do not switch to `fail_open` as a workaround; that requires a Design Authority disposition |
| High `sf_ai_schema_failures_total` | A provider or prompt change is producing invalid output. Check recent `prompt.version.published` and `model.binding.changed`. Roll back the prompt/model binding; the eval suite should have caught it — file a gap |
| Provider outage | Circuit breaker + fallback chain handle it; verify fallbacks are configured for the affected purpose; the rest of the platform is unaffected |
| Budget exhausted | `quota.tokens_exhausted`; contact the tenant admin; an overage requires an approved exception |
| Latency budget exhaustion > 1% | Check guardrail p95s; scale the slow guardrail; consider raising its budget only with a documented decision |

## 7. Kubernetes / runtime

| Symptom | Action |
|---------|--------|
| CrashLoopBackOff | `kubectl describe pod` → last state reason; check config/secret refs; check migration state; check `/readyz` output in logs |
| OOMKilled | Compare limits to actual usage; look for a large artifact body being loaded whole (bodies > 256 KB should stream from object storage — a regression here is a bug, raise it) |
| ImagePullBackOff | Registry auth, digest existence, admission signature verification (an unsigned image is rejected by policy — check the provenance) |
| Readiness flapping | `/readyz` names the failing dependency; treat that dependency |
| Rollout stuck | `kubectl rollout status`; check PDB blocking eviction; check node capacity |

## 8. Certificate / secret rotation

1. Rotation is dual-read: the app accepts old and new during the window.
2. Rotate in the secret store; the app reloads on notification (or on the next restart).
3. Verify with `/readyz` and a smoke journey before revoking the old credential.
4. Every rotation is audited; record the change in the change log.

## 9. Scaling

| Signal | Action |
|--------|--------|
| API CPU > 70% sustained / p95 latency near SLO | HPA handles it; if at max replicas, raise the ceiling and check DB pool headroom |
| Worker consumer lag | KEDA scales on lag; if at max, split roles into separate deployments (`--roles=`) |
| Gateway inflight high | Scale the gateway and the specific slow guardrail independently |
| DB CPU/IO high | Add a read replica; check for a missing index on a new query; check graph query depth |

## 10. Maintenance mode

`specforge-cli maintenance enable --reason "…" --eta 30m` — the API returns `503` with a problem
document for mutations while keeping reads available where safe, the UI shows a banner, and the
action is audited. Always set an ETA; always disable explicitly.

## 11. Common commands

```bash
# Health and state
kubectl -n specforge get pods,deploy,hpa
curl -s https://api.specforge.example/readyz | jq

# Verification
specforge-cli verify-audit   --tenant <t> [--from N --to M]
specforge-cli verify-content --tenant <t> --since 24h
specforge-cli trace upstream --project <p> --artifact CODE-...

# Events
specforge-cli outbox status
specforge-cli dlq list --group drift
specforge-cli dlq replay --group drift --since 2026-08-20T00:00:00Z

# Projections
specforge-cli rebuild-projections --project <p>

# Migrations
specforge-migrate status
specforge-migrate up
```

## 12. Escalation

| Situation | Escalate to |
|-----------|-------------|
| Integrity or audit-chain violation | Security (immediate) → Incident Commander |
| Suspected cross-tenant exposure | Security (immediate) → Compliance → tenant notification path |
| Data loss during recovery | Engineering Lead → Compliance (disposition required) |
| Governance control failure (a gate did not fire) | Design Authority (a gate failure is a control failure, not just a bug) |
| Sustained SLO breach > 1 h | Engineering Lead → Architect |
