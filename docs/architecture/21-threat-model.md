# SpecForge — Threat Model

**Status:** Baseline v1.0
**Method:** STRIDE per trust boundary, plus AI-specific threats (OWASP LLM Top 10) and
supply-chain threats. Reviewed by the Design Authority; revisited each phase.

---

## 1. Assets

| Asset | Why it matters | Impact if compromised |
|-------|---------------|----------------------|
| A1 Approved artifacts + approval evidence | The assurance record; regulatory evidence | Catastrophic — the platform's entire value proposition |
| A2 Audit trail | Tamper-evident history | Catastrophic |
| A3 Tenant artifact content (PRDs, specs, source) | Customer IP and strategy | Severe |
| A4 Credentials/secrets (IdP, VCS, cloud, LLM keys) | Lateral movement | Severe |
| A5 Governance policies & dispositions | Controls integrity | Severe |
| A6 Generated code & pipelines | Path to the customer's production | Severe |
| A7 Cluster read access to customer environments | Recon and, if writable, disruption | High |
| A8 AI budgets/quotas | Financial | Moderate |

## 2. Adversaries

| ID | Adversary | Capability | Motivation |
|----|-----------|-----------|-----------|
| T1 | External unauthenticated attacker | Internet access, automated tooling | Data theft, ransom, disruption |
| T2 | Malicious tenant user | Valid credentials in tenant A | Access tenant B, escalate, bypass gates |
| T3 | Compromised low-privilege user | Stolen session/API key | Escalate, exfiltrate |
| T4 | Malicious insider (platform operator) | Infrastructure/DB access | Alter approvals, hide evidence |
| T5 | Supply-chain attacker | Compromised dependency, base image, or guardrail container | Code execution in the platform |
| T6 | Malicious content author | Uploads a document or repository | Prompt injection, parser exploit, resource exhaustion |
| T7 | Compromised LLM provider | Sees prompts, returns crafted output | Data exposure, poisoned artifacts |

## 3. STRIDE by boundary

### B0→B1 Internet → Edge

| Threat | STRIDE | Mitigation |
|--------|--------|-----------|
| Credential stuffing, brute force | S | IdP-side lockout, MFA, WAF rate limits, per-IP throttling |
| Token forgery (`alg:none`, HMAC confusion) | S | Asymmetric-only verification, pinned JWKS, strict `aud`/`iss` |
| DDoS | D | CDN + WAF, per-tenant/principal token buckets, body size caps, query complexity caps |
| Webhook spoofing | S | HMAC verification before parsing, replay window, source allowlist |

### B1→B2→B3 Edge → BFF → API

| Threat | STRIDE | Mitigation |
|--------|--------|-----------|
| Session theft via XSS | S/I | BFF pattern (no token in JS), HttpOnly+Secure+SameSite cookies, strict CSP with nonces, no `dangerouslySetInnerHTML` without sanitizer |
| CSRF | S | SameSite=Lax + double-submit token on state-changing posts |
| BFF bypass (direct API call) | E | API authorizes independently; mTLS + service token required from BFF; network policy restricts ingress |
| Parameter tampering (tenant/project in path) | E | Tenant derived from token claim; path must agree or 403 + audit |

### B3 API internals

| Threat | STRIDE | Mitigation |
|--------|--------|-----------|
| **Cross-tenant read via forged IDs (T2)** | I/E | Defence in depth: authz tenant predicate → service `TenantContext` → **RLS with `FORCE`** → storage prefix policy → cache namespace. Verified by the isolation suite on every release |
| Missing authorization on a new route | E | `make lint-routes`: a route without a declared permission fails the build |
| Privilege escalation via role self-assignment | E | `role:assign` requires tenant_admin; SoD-6 blocks service accounts from approvals; grant changes audited and event-driven cache invalidation |
| Approval bypass | T/E | FSM refuses illegal transitions; gates evaluated server-side; SoD four-eyes; step-up MFA; DB trigger blocks sealed-row mutation |
| IDOR on artifacts | I | Artifact IDs are project-scoped and RLS-filtered; a valid ID from another tenant returns 404 |
| Mass export | I | Export is a permissioned, audited, rate-limited async job; anomaly alert on volume |
| SSRF via repository/webhook URLs | I | Allowlist + re-resolving dialer blocking private/link-local ranges at connect time |
| Path traversal / zip bomb in uploads | D/E | Hardened extractor (no `..`, no absolute paths, no symlinks/devices), ratio and size caps, sandboxed worker |
| SQL injection | I/E | Parameterized queries only; `make lint-sql` forbids formatted SQL |

### B3→B5 Data plane

| Threat | STRIDE | Mitigation |
|--------|--------|-----------|
| **Insider alters an approved artifact (T4)** | T | Content addressing + read-path hash verification + object-lock WORM evidence + hash-chained audit anchored to WORM. DB-only tampering is detectable and the evidence copy is immutable |
| **Insider deletes audit records (T4)** | T/R | No `DELETE`/`UPDATE` grant, trigger raises, partitions retained, hourly anchor to object-lock storage, mirror to customer SIEM |
| Backup theft | I | Encrypted backups with CMK; restore requires separate IAM; access audited |
| Cache poisoning | T | Namespaced keys built server-side; cached values are non-authoritative and re-verified on use for anything security-relevant |
| Event tampering | T | `payload_hash` in the envelope; consumers verify; broker TLS+SASL with per-service ACLs |

### B3→B4 Guardrails / B3→B6 Third parties

| Threat | STRIDE | Mitigation |
|--------|--------|-----------|
| Malicious guardrail container (T5) | I/E | No network egress, read-only rootfs, no capabilities, resource limits, signed images, conformance tests |
| Guardrail bypass | E | Provider egress allowed only from the gateway (network policy); the gateway has no code path to call a provider outside the chain; bypass attempt is tested in the cluster suite |
| LLM provider sees sensitive data (T7) | I | PII redaction pre-inference, secret-egress guardrail, tenant provider allowlist and residency policy, zero-retention provider settings, no tenant identifiers in prompts |
| Poisoned model output (T7) | T | Schema validation, grounding cross-check, post-inference safety guardrail, human approval for anything authoritative |
| Cost exhaustion (T8) | D | Per-tenant token budgets, cost-guard pre-inference, circuit breakers, budget alerts |

### AI-specific (OWASP LLM)

| ID | Threat | Mitigation |
|----|--------|-----------|
| LLM01 | Prompt injection from ingested documents/repos (T6) | Untrusted content only in declared, delimited data channels; injection guardrail; **output schema validation** means an injected instruction cannot yield a valid malicious artifact without also passing governance; tools are typed, allowlisted and re-authorized against the *user's* permissions |
| LLM02 | Insecure output handling | Never execute model output; generated code goes through PR review and the full gate set; no dynamic `eval` anywhere |
| LLM04 | Model DoS | Token/rate budgets, context caps, deadline propagation |
| LLM06 | Sensitive information disclosure | Redaction, egress guardrails, per-tenant isolation of retrieval and embeddings |
| LLM07 | Insecure plugin/tool design | Typed tool interface, per-tool permission checks, no shell/HTTP/DB tools |
| LLM08 | Excessive agency | AI is advisory; every authoritative write requires governance and (by default) a human |
| LLM09 | Overreliance | Generated artifacts labelled `generator.kind=INFERENCE`; grounding checks; mandatory review sampling |
| LLM10 | Model theft/abuse | Provider keys only in the gateway; usage metered and anomaly-alerted |

### Supply chain (T5)

| Threat | Mitigation |
|--------|-----------|
| Malicious dependency | SCA + `govulncheck` gates, lockfiles verified, `-mod=readonly`, restricted auto-updates |
| Compromised base image | Digest-pinned distroless bases, container scanning, rebuild cadence |
| Build system compromise | Ephemeral runners, OIDC to cloud (no static keys), signed images, SLSA provenance, admission verification |
| Malicious generated pipeline | Generated pipelines are artifacts subject to gates; the customer's CI still enforces its own approvals |

## 4. Residual risks

| Risk | Why it remains | Compensating control | Owner | Review |
|------|---------------|---------------------|-------|--------|
| Full infrastructure compromise (root on all systems, all keys) | No system survives total key compromise | Audit anchoring to WORM with a separate credential path; external SIEM mirror makes tampering detectable even if not preventable | Security | Quarterly |
| Sophisticated prompt injection in a novel form | Detection is heuristic | Schema validation + human approval mean injection alone cannot produce an authoritative artifact | AI Platform | Per phase |
| Customer misconfiguration (over-broad roles, `fail_open` guardrails) | Customer autonomy | Secure defaults, `fail_open` requires a disposition, posture warnings on the dashboard | Design Authority | Continuous |
| Insider with `platform_admin` + `compliance` collusion executing a purge | Two-person control is the limit | Purge certificates in platform WORM storage; tenant notification; legal-hold check fails closed | Compliance | Annual |

## 5. Verification

Each mitigation maps to at least one automated test:

| Mitigation | Test |
|-----------|------|
| Tenant isolation | `test/isolation` — every route, both directions, DB-level row assertions |
| Sealed immutability | Repository test attempting update on APPROVED → expect trigger error |
| Audit tamper evidence | Mutate a record row directly, run `VerifyChain` → expect failure at the exact sequence |
| Route authorization coverage | `make lint-routes` + a generated authz matrix test per route per role |
| Guardrail bypass | Cluster test asserting no egress path from api/worker to provider FQDNs |
| Fail-closed behaviour | Guardrail chaos tests (kill, slow, garble) |
| Upload hardening | Fuzz corpus + zip-bomb + traversal fixtures |
| SSRF | Fixtures targeting 169.254.169.254, 127.0.0.1, DNS-rebinding hosts |
| Step-up enforcement | Approval without recent MFA → 401 `step_up_required` |
