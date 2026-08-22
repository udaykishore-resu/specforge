# SpecForge — Identity & Authorization Model

**Status:** Baseline v1.0
**Owner:** Enterprise Security Architect

---

## 1. Requirements this model must satisfy

- Multi-tenant SaaS **and** single-tenant enterprise deployment from one codebase.
- Enterprise IdP via OIDC/OAuth2 today, SAML-ready without redesign.
- Roles at both tenant and project scope, with the twelve roles from the brief §17.
- Isolation that survives a forged identifier: a valid token for tenant A must not be able to read
  tenant B even if the caller guesses B's artifact IDs.
- Auditable authorization: every deny is explainable, every allow is attributable.

## 2. Model: RBAC core with ABAC refinements

**Decision:** role-based at the coarse layer, attribute-based at the fine layer.

```
Decision = f(Principal, Action, Resource, Environment)

ALLOW ⟺  tenant_match(Principal, Resource)
      ∧  scope_grants(Principal, Resource) ⊇ {required_permission(Action)}
      ∧  ¬ denied_by_policy(Principal, Action, Resource, Environment)
      ∧  segregation_of_duties_ok(Principal, Action, Resource)
```

Deny always wins. Absence of a grant is a deny (default-deny).

### 2.1 Why not pure ABAC

Pure ABAC is unexplainable to auditors at scale and slow in the hot path. Pure RBAC cannot express
"the author may not be the sole approver" or "exception grants require Design Authority membership".
The split keeps the hot path a set-membership check (sub-microsecond, cacheable) and confines
attribute evaluation to a small number of sensitive actions.

## 3. Principals

| Kind | Source | Credential | Notes |
|------|--------|-----------|-------|
| `USER` | Enterprise IdP via OIDC | ID/access token (JWT) | Mapped to a platform principal on first login (JIT provisioning) |
| `SERVICE_ACCOUNT` | Created by tenant admin | API key (hashed, prefixed, rotatable) or client-credentials JWT | Scoped to a permission subset; cannot hold approval permissions |
| `SYSTEM` | Internal | mTLS workload identity | Used by workers; cannot act on behalf of a user without an explicit delegation record |

**Delegation:** a worker acting for a user carries `on_behalf_of` in the principal context. The audit
record shows both the acting system and the originating user. A system principal may never
*escalate*: the effective permission set is the intersection of the system's and the user's.

## 4. Roles and permissions

Permissions are `<resource>:<action>` strings. Roles are named permission bundles, versioned as
part of the tenant policy set.

### 4.1 Permission namespace (abridged; full list in `configs/rbac/permissions.yaml`)

```
tenant:read tenant:update tenant:suspend tenant:purge
project:create project:read project:update project:archive
principal:read principal:invite role:assign apikey:create apikey:revoke
artifact:create artifact:read artifact:edit artifact:submit artifact:review
artifact:approve artifact:freeze artifact:delete
prd:discovery prd:upload prd:approve
spec:generate spec:approve
model:generate model:edit
code:generate code:read repo:connect repo:ingest
sync:run proposal:submit proposal:approve
gate:evaluate gate:override policy:read policy:update
exception:request exception:grant disposition:record
designauthority:decide
pipeline:read pipeline:trigger pipeline:approve
deployment:read deployment:approve deployment:rollback
runtime:read incident:ack incident:manage escalation:manage
scan:run finding:read finding:suppress
ai:invoke ai:config prompt:read prompt:publish guardrail:config
audit:read audit:export
```

### 4.2 Role → permission matrix

`R` read · `W` write · `A` approve · `—` none

| Permission group | Platform Admin | Tenant Admin | Product Owner | Business Analyst | Architect | Developer | QA | DevOps | Security | Compliance | Auditor | Viewer |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| tenant admin | W* | W | — | — | — | — | — | — | — | — | R | — |
| project | W* | W | W | R | W | R | R | R | R | R | R | R |
| principals / roles | W* | W | — | — | — | — | — | — | R | R | R | — |
| PRD content | —† | R | W | W | R | R | R | — | R | R | R | R |
| PRD approve | — | — | **A** | — | A‡ | — | — | — | — | — | — | — |
| Specifications | —† | R | W | W | W | R | R | — | R | R | R | R |
| Spec approve | — | — | A | — | A | — | — | — | — | — | — | — |
| BPMN / models | —† | R | R | W | W | R | R | — | R | R | R | R |
| Architecture | —† | R | R | R | **W/A** | R | R | R | R | R | R | R |
| Code generation | — | R | — | — | W | W | R | R | R | — | R | R |
| Repositories | — | W | — | — | W | W | R | W | R | — | R | — |
| Proposals | — | R | A | W | A | W | W | — | A | A | R | — |
| Gates: evaluate | — | R | R | R | R | R | R | R | R | R | R | — |
| Gate override | — | — | — | — | — | — | — | — | — | — | — | — |
| Exceptions: request | — | W | W | W | W | W | W | W | W | W | — | — |
| Exceptions: grant | — | — | — | — | **A**§ | — | — | — | **A**§ | **A**§ | — | — |
| Design Authority | — | — | — | — | **A**§ | — | — | — | A§ | A§ | — | — |
| Pipelines | — | R | R | — | R | W | R | **W** | R | R | R | R |
| Deployment approve | — | — | — | — | A | — | — | **A** | A | A | — | — |
| Runtime / incidents | R* | R | R | — | R | R | R | **W** | R | R | R | R |
| Scans / findings | — | R | R | — | R | R | R | R | **W** | R | R | — |
| Finding suppression | — | — | — | — | — | — | — | — | **A** | A | — | — |
| AI config / guardrails | R* | W | R | R | R | R | — | — | **W** | R | R | — |
| Prompt publish | — | W | — | — | W | W | — | — | W | — | R | — |
| Audit read/export | R* | R | — | — | R | — | — | — | R | **R/W** | **R/W** | — |

\* Platform Admin operates the platform, not the tenant's content — see §6 break-glass.
† Platform Admin has **no** default read access to tenant artifact content.
‡ Architect may approve a PRD only if the tenant enables `architect_can_approve_prd`.
§ Exception granting and Design Authority decisions require *membership in the Design Authority
body* in addition to the role — see §7.

Roles are additive; a principal's effective permission set is the union of role grants at tenant
scope and at the specific project scope, minus explicit denies.

## 5. Scoping

```
Grant := (principal_id, tenant_id, project_id | NULL, role, granted_by, granted_at, expires_at?)
```

- `project_id = NULL` → tenant-wide grant, applies to all current and future projects.
- Project grants never widen tenant grants for *other* projects.
- Grants may expire (`expires_at`), supporting time-boxed access (contractors, break-glass).

**Resource scoping rule:** every resource in the system carries `tenant_id`, and every
project-owned resource carries `project_id`. There is no global resource except the platform's own
configuration. Authorization checks the resource's own scope columns — never a scope inferred from
the request path.

## 6. Enforcement layers (defence in depth)

| # | Layer | Mechanism | Fails how |
|---|-------|-----------|-----------|
| 1 | Edge | Token validation: issuer, audience, `exp`, `nbf`, signature via cached JWKS; mTLS for service-to-service | 401 |
| 2 | Tenant resolution | `tenant_id` derived from the token claim + host/subdomain, **never** from a body field or a path segment the client controls alone; mismatch → deny | 403 + `security.tenant_mismatch` audit |
| 3 | Authorization middleware | Route-declared required permission checked against the principal's cached permission set | 403 |
| 4 | Application | Service methods take `TenantContext`; repositories refuse queries without it (compile-time: repository constructors require the context type) | panic-free error |
| 5 | Database | PostgreSQL Row-Level Security using `SET LOCAL app.tenant_id`; every tenant-scoped table has a `FORCE ROW LEVEL SECURITY` policy | 0 rows |
| 6 | Object storage | Per-tenant key prefix + IAM/bucket policy conditioned on the prefix; per-tenant KMS key in `dedicated` isolation mode | AccessDenied |
| 7 | Cache | Key namespace `sf:{tenant_id}:…`; a client cannot construct a key outside its namespace because the namespace is injected server-side | miss |
| 8 | Events | `tenant_id` in the key and envelope; consumers open a tenant-scoped session before handling | poison → DLQ |

Layer 5 is the one that makes forged-ID attacks structurally impossible: even a service bug that
omits a `WHERE tenant_id = …` returns nothing, because the session's RLS predicate applies.

### 6.1 Break-glass

`platform_admin` can obtain temporary tenant-content access only through a **break-glass grant**:
requires a second approver, a stated reason, a maximum TTL of 4 hours, emits
`security.breakglass.granted`, notifies the tenant admin and the tenant's security contact, and is
flagged in the tenant's audit export. All actions during the window are tagged `breakglass=true`.

## 7. Segregation of duties (ABAC layer)

Evaluated for a small, explicit set of sensitive actions:

| Rule | Statement |
|------|-----------|
| SoD-1 four-eyes | The approver of an artifact version must not be its sole author, when `policy.four_eyes = true` (default on for PRD, ARCH, POLICY types). |
| SoD-2 exception independence | The principal requesting an exception may not grant it. |
| SoD-3 Design Authority membership | `exception:grant` and `designauthority:decide` additionally require membership in the project's or tenant's Design Authority body with a quorum defined in policy. |
| SoD-4 deploy independence | The principal approving a production deployment must not be the sole author of the changes in it, when `policy.prod_deploy_four_eyes = true`. |
| SoD-5 suppression independence | A `finding:suppress` requires `security` or `compliance` role and cannot be performed by the code's author. |
| SoD-6 service accounts | A `SERVICE_ACCOUNT` may never hold any `*:approve`, `exception:grant`, or `designauthority:decide` permission. Enforced at grant time and re-checked at decision time. |

Attribute inputs: `resource.created_by`, `resource.contributors[]`, `principal.id`,
`principal.da_membership`, `policy.*`, `env.mfa_satisfied`, `env.breakglass`.

**Step-up authentication:** actions in the sensitive set require a token whose `auth_time` is within
`policy.step_up_max_age` (default 15 min) and whose `amr` includes an MFA method; otherwise the API
returns `401` with `WWW-Authenticate: step_up_required`.

## 8. Deployment modes

| Mode | Tenants per deployment | Database | Storage | Keys | Use |
|------|-----------------------|----------|---------|------|-----|
| `shared` (SaaS) | many | one cluster, shared schema + RLS | shared bucket, per-tenant prefix | platform KMS key, per-tenant data key | Default SaaS |
| `dedicated_schema` | many | one cluster, schema per tenant + RLS | per-tenant bucket | per-tenant KMS key | Regulated SaaS |
| `single_tenant` | one | dedicated cluster | dedicated buckets | customer-managed KMS | Enterprise on-prem/VPC |

The same code runs in all three. The isolation mode is a tenant attribute resolved at startup for
`single_tenant` and per-request for the others; storage/DB adapters select the routing strategy.
**RLS is enabled in every mode**, including `single_tenant`, so the code path is never untested.

## 9. Token handling

- Accepted: OIDC ID token (interactive) and access token (API), RS256/ES256, JWKS cached with a
  5-minute refresh and negative-cache on failure.
- Required claims: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `amr`, plus a tenant claim
  (configurable claim name, default `https://specforge.io/tenant`).
- Role mapping: IdP groups/roles → platform roles via a tenant-scoped, versioned mapping table.
  Unmapped groups grant nothing. Mapping changes are audited and emit `role.assignment.changed`.
- **No session state in the API.** The browser holds an HttpOnly, `SameSite=Lax`, `Secure` cookie
  containing an opaque reference; the BFF exchanges it for the upstream token. Tokens never reach
  browser JavaScript.
- Refresh handled by the BFF; logout revokes the reference and calls the IdP end-session endpoint.

**SAML readiness:** the platform depends only on the internal `Principal` + `Assertion` types. A
SAML adapter implements the same `IdentityProvider` port (`Authenticate`, `Claims`, `Logout`,
`Metadata`) with no changes above the port.

## 10. Authorization decision path & performance

```
Request → JWT verify (cached JWKS)
        → principal resolve (Redis, 60 s TTL, invalidated by role.assignment.changed)
        → permission set (bitset over the permission namespace, computed on cache fill)
        → route permission check (bitset AND)         ← O(1)
        → [sensitive action?] ABAC evaluation (CEL)   ← only for the SoD set
        → handler (TenantContext) → repository (RLS session) → DB
```

p99 budget for the authorization path: **< 3 ms** excluding DB. The permission bitset makes the
common case a single word comparison.

## 11. Auditing authorization

Every `DENY` writes an audit record with the principal, action, resource, the *failing rule ID*, and
the policy set version — so an auditor can reconstruct why access was refused. Every `ALLOW` on a
sensitive action writes a record with the satisfied rule IDs and the attributes that were evaluated.
Routine `ALLOW`s on read actions are sampled (default 1%) plus always recorded for `auditor` role
activity and break-glass windows.
