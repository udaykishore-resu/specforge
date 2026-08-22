# SpecForge — API Specification

**Status:** Baseline v1.0
**Machine-readable source of truth:** `api/openapi/specforge.v1.yaml` (OpenAPI 3.1).
Handlers and DTOs are checked against it in CI (`make openapi-verify`); drift fails the build.

---

## 1. Principles

- **Versioned path prefix**: `/api/v1/…`. Breaking changes mint `/api/v2`; both run during a
  deprecation window with `Deprecation` and `Sunset` headers on the old one.
- **REST for control/CRUD**, `POST /…:verb` for non-CRUD state transitions (the colon-verb form
  keeps the resource identity explicit and avoids overloading PATCH semantics).
- **SSE for streams** the browser consumes (AI token streaming, pipeline/deployment/runtime events);
  **WebSocket** only where the client must also send (collaborative editing, Phase 5+).
- **gRPC internally** between `api`, `worker` and `gateway` where the call is hot and typed.
- Every response carries `X-Request-Id` and `traceparent`. Errors are RFC 9457 problem+json.
- All list endpoints are cursor-paginated (`?cursor=&limit=`), never offset.
- Mutating endpoints require `Idempotency-Key`.

## 2. Conventions

| Aspect | Rule |
|--------|------|
| Auth | `Authorization: Bearer <JWT>` or `X-Api-Key`. Browser uses the BFF; cookies never reach the API. |
| Tenancy | Resolved from the token claim; `/tenants/{tenantId}` in the path must match or `403`. |
| Content type | `application/json; charset=utf-8`; uploads `multipart/form-data`. |
| Time | RFC 3339 UTC with `Z`. |
| Money/cost | Minor units + currency code, never floats. |
| Concurrency | `If-Match: <version_no>` on updates → `412` on mismatch. |
| Partial responses | `?fields=` projection on read-heavy artifact endpoints. |
| Rate limits | `RateLimit-*` headers; `429` with `Retry-After`. |

## 3. Error model

```json
{
  "type": "https://specforge.io/problems/artifact-sealed",
  "title": "Artifact version is sealed",
  "status": 409,
  "detail": "PRD-001 v4 is APPROVED and cannot be modified. Create a new version.",
  "instance": "/api/v1/tenants/t_1/projects/p_1/artifacts/PRD-001/versions/4",
  "code": "artifact.sealed_immutable",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "errors": [{ "field": "content", "code": "immutable" }]
}
```

| HTTP | Kind | Typical `code` |
|------|------|----------------|
| 400 | INVALID_ARGUMENT | `validation.failed`, `schema.invalid` |
| 401 | UNAUTHENTICATED | `auth.token_invalid`, `auth.step_up_required` |
| 403 | PERMISSION_DENIED | `authz.denied`, `authz.tenant_mismatch`, `sod.violation` |
| 404 | NOT_FOUND | `artifact.not_found` |
| 409 | CONFLICT | `artifact.sealed_immutable`, `idempotency.key_reuse`, `concurrency.stale_version` |
| 412 | FAILED_PRECONDITION | `gate.blocked`, `artifact.not_in_review` |
| 422 | INVALID_ARGUMENT | `content.schema_validation_failed` |
| 429 | RESOURCE_EXHAUSTED | `ratelimit.exceeded`, `quota.tokens_exhausted` |
| 500 | INTERNAL | `internal.error` |
| 503 | UNAVAILABLE | `dependency.unavailable` |

## 4. Phase 1 endpoints (implemented)

### Health & meta
```
GET  /healthz                     liveness  (no auth, no deps)
GET  /readyz                      readiness (checks db, redis, objstore, broker)
GET  /api/v1/version              build info
GET  /api/v1/openapi.json         the spec itself
GET  /metrics                     Prometheus (cluster-internal only)
```

### Authentication
```
GET  /api/v1/auth/login           302 → IdP authorize (PKCE, state, nonce)
GET  /api/v1/auth/callback        code exchange → session reference cookie (BFF)
POST /api/v1/auth/logout          revoke reference + IdP end-session
GET  /api/v1/auth/me              current principal, roles, effective permissions
POST /api/v1/auth/step-up         initiate step-up when 401 step_up_required
```

### Tenants
```
POST   /api/v1/tenants                     platform_admin           → 201 Tenant
GET    /api/v1/tenants                     list (scoped to caller)
GET    /api/v1/tenants/{tenantId}
PATCH  /api/v1/tenants/{tenantId}          tenant:update, If-Match
POST   /api/v1/tenants/{tenantId}:suspend  tenant:suspend
POST   /api/v1/tenants/{tenantId}:reinstate
GET    /api/v1/tenants/{tenantId}/settings
PUT    /api/v1/tenants/{tenantId}/settings
```

### Principals, roles, API keys
```
GET    /api/v1/tenants/{t}/principals
POST   /api/v1/tenants/{t}/principals:invite
GET    /api/v1/tenants/{t}/principals/{id}/roles
POST   /api/v1/tenants/{t}/principals/{id}/roles        role:assign  (body: role, projectId?, expiresAt?)
DELETE /api/v1/tenants/{t}/principals/{id}/roles/{ra}
POST   /api/v1/tenants/{t}/api-keys                     → secret shown once
DELETE /api/v1/tenants/{t}/api-keys/{keyId}
GET    /api/v1/tenants/{t}/idp-mappings
PUT    /api/v1/tenants/{t}/idp-mappings
```

### Projects
```
POST   /api/v1/tenants/{t}/projects        {key, name, description}
GET    /api/v1/tenants/{t}/projects
GET    /api/v1/tenants/{t}/projects/{p}
PATCH  /api/v1/tenants/{t}/projects/{p}
POST   /api/v1/tenants/{t}/projects/{p}:archive
POST   /api/v1/tenants/{t}/projects/{p}:restore
```

### Artifacts (graph core)
```
POST   …/projects/{p}/artifacts                              create artifact + v1 draft
GET    …/projects/{p}/artifacts                              filter by type,status,label
GET    …/projects/{p}/artifacts/{aid}
GET    …/projects/{p}/artifacts/{aid}/versions
GET    …/projects/{p}/artifacts/{aid}/versions/{v}           verifies content hash
PUT    …/projects/{p}/artifacts/{aid}/versions/{v}           draft only, If-Match
POST   …/projects/{p}/artifacts/{aid}/versions/{v}:submit
POST   …/projects/{p}/artifacts/{aid}/versions/{v}:request-changes
POST   …/projects/{p}/artifacts/{aid}/versions/{v}:approve   step-up + SoD + gates
POST   …/projects/{p}/artifacts/{aid}/versions/{v}:freeze
POST   …/projects/{p}/artifacts/{aid}:revise                 → new draft version
GET    …/projects/{p}/artifacts/{aid}/versions/{v}/evidence
GET    …/projects/{p}/artifacts/{aid}/diff?from=3&to=4       type-aware diff
```

### Trace links & traceability queries
```
POST   …/projects/{p}/links
GET    …/projects/{p}/links?from=&to=&type=&status=
POST   …/projects/{p}/links/{linkId}:accept        disposition required for LLM_PROPOSED
POST   …/projects/{p}/links/{linkId}:reject
GET    …/projects/{p}/trace/upstream?artifact=CODE-…&types=SPEC,REQ,PRD
GET    …/projects/{p}/trace/downstream?artifact=REQ-…
GET    …/projects/{p}/trace/impact?artifact=SPEC-…&version=3
GET    …/projects/{p}/trace/paths?from=CODE-…&to=PRD-001
```

These four endpoints answer the five traceability questions from `00-product-requirements.md §5`;
each returns full paths with the link type and origin of every hop.

### Audit
```
GET  /api/v1/tenants/{t}/audit?from=&to=&action=&actor=&outcome=&cursor=
GET  /api/v1/tenants/{t}/audit/{sequence}
POST /api/v1/tenants/{t}/audit:verify        {from, to} → chain verification report
POST /api/v1/tenants/{t}/audit:export        → signed NDJSON bundle (async job)
```

## 5. Later-phase endpoints (specified in OpenAPI, implemented per phase)

| Phase | Surface |
|-------|---------|
| 2 | `…/prd/sessions`, `…/prd/sessions/{id}/messages` (SSE stream), `…/prd/documents` (upload/parse), `…/prd/{id}/change-requests` |
| 3 | `…/specs:generate`, `…/requirements`, `…/specs/{id}/criteria`, `…/specs/{id}/machine-readable` |
| 5 | `…/models/bpmn:generate`, `…/models/bpmn/{id}:validate`, `…/models/c4`, `…/models/erd`, `…/models/openapi` |
| 6 | `…/codegen:plan`, `…/codegen:run`, `…/codegen/runs/{id}` (SSE), `…/codegen/runs/{id}/artifacts` |
| 7 | `…/repositories`, `…/repositories/{id}:ingest`, `…/repositories/{id}/analysis` |
| 8 | `…/sync:run`, `…/drift`, `…/proposals`, `…/proposals/{id}:approve`, `…/consistency` |
| 9 | `…/pipelines`, `…/pipelines/{id}/runs`, `…/runs/{id}/events` (SSE), `…/runs/{id}/root-cause` |
| 10 | `…/gates/{gate}:evaluate`, `…/governance/cases`, `…/exceptions`, `…/dispositions`, `…/policies` |
| 11 | `/api/v1/ai/chat` (SSE), `/api/v1/ai/guardrails`, `…/prompts`, `…/models/bindings`, `…/ai/usage` |
| 12 | `…/workloads`, `…/workloads/{id}/pods`, `…/incidents`, `…/incidents/{id}:ack`, `…/escalations` |

## 6. Streaming contracts

**SSE event frames** (all streams):

```
event: message
id: 01J9Z8...
data: {"type":"token","seq":42,"content":"…"}

event: heartbeat
data: {"ts":"2026-08-20T02:51:00Z"}

event: error
data: {"code":"guardrail.blocked","detail":"…","trace_id":"…"}

event: done
data: {"reason":"complete","usage":{"input":1204,"output":880},"inference_id":"inf_…"}
```

Rules: client reconnects with `Last-Event-ID`; the server replays from its buffer where the stream
is replayable (pipeline/runtime events) and restarts where it is not (token streams), signalling
`restart: true`. Heartbeat every 15 s. A dropped consumer never blocks the producer — the hub drops
to a `lag` notice rather than buffering unboundedly.

## 7. Webhooks (inbound)

```
POST /api/v1/webhooks/github     X-Hub-Signature-256, HMAC verified, replay window 5 min
POST /api/v1/webhooks/jenkins    HMAC + allowlisted source
POST /api/v1/webhooks/scanner/{vendor}
```

All inbound webhooks: signature verified before parsing, body size capped, event ID de-duplicated,
processed asynchronously (accepted with `202` + queued), and audited.

## 8. API security controls

- OAuth2 scopes map 1:1 onto the permission namespace; a token's scopes intersect with the
  principal's role grants (least privilege wins).
- Every route declares its required permission in code; a route without a declaration fails the
  `make lint-routes` check, so it is impossible to ship an unprotected endpoint by omission.
- Request body schema validation before any business logic; unknown fields rejected (`strict`).
- Response redaction: a shared `redact` marshaller strips secrets, tokens, PII-flagged fields and
  internal identifiers based on struct tags.
- CORS: explicit allowlist per tenant's configured origins; no wildcard, credentials allowed only
  for the BFF origin.
- Security headers: HSTS (2 y, preload), `Content-Security-Policy` with nonces,
  `X-Content-Type-Options`, `Referrer-Policy: strict-origin-when-cross-origin`,
  `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`.
