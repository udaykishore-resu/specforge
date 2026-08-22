# SpecForge — Low Level Design

**Status:** Baseline v1.0
Scope: the design contracts implemented in Phase 1 plus the interfaces Phases 2–12 plug into.

---

## 1. Package layout and dependency rule

```
cmd/
  specforge-api/       main; wiring only
  specforge-worker/
  specforge-gateway/
  specforge-migrate/
internal/
  platform/            shared, domain-free
    config/ log/ otel/ errors/ httpx/ id/ jcs/ hash/ fsm/ validate/
    db/ (pool, tx, RLS session, migrations)  outbox/  cache/  objstore/
    authn/ authz/ ratelimit/ idempotency/ schema/
    adapters/aws|local
  tenancy/ identity/ audit/ artifactgraph/ prd/ spec/ model/
  codegen/ reverse/ sync/ governance/ delivery/ runtime/ compliance/ aiplatform/
      domain/          entities, value objects, invariants, FSM tables — no I/O
      app/             use cases, orchestration, transactions, ports (interfaces)
      infra/           postgres, objstore, http clients — implements ports
      transport/       HTTP handlers, DTOs, OpenAPI mapping
    ports/             cross-module contracts consumed by other modules
api/openapi/           OpenAPI 3.1 specs (source of truth for DTOs)
schemas/               JSON Schemas: artifacts, events, policies
migrations/            numbered, forward-only SQL
```

Enforced import rules (`make lint-arch`):

1. `*/domain` may import only stdlib + `platform/types`, `platform/errors`, `platform/fsm`.
2. `*/app` may import its own `domain`, `platform/*`, and other modules' `ports` — never another
   module's `domain`, `app`, or `infra`.
3. `*/infra` may import its own `domain` and `app` ports, plus `platform/*`.
4. `*/transport` may import its own `app` only.
5. `sync/*` may not import `artifactgraph/ports.ArtifactWriter`.
6. Nothing may import a provider SDK outside `aiplatform/infra`.

## 2. Core platform contracts

### 2.1 Errors

```go
package errors

type Kind string
const (
    KindInvalid      Kind = "INVALID_ARGUMENT"
    KindUnauthorized Kind = "UNAUTHENTICATED"
    KindForbidden    Kind = "PERMISSION_DENIED"
    KindNotFound     Kind = "NOT_FOUND"
    KindConflict     Kind = "CONFLICT"
    KindPrecondition Kind = "FAILED_PRECONDITION"
    KindExhausted    Kind = "RESOURCE_EXHAUSTED"
    KindInternal     Kind = "INTERNAL"
    KindUnavailable  Kind = "UNAVAILABLE"
    KindTimeout      Kind = "DEADLINE_EXCEEDED"
    KindTampered     Kind = "INTEGRITY_VIOLATION"
)

type Error struct {
    Kind    Kind
    Code    string            // stable machine code, e.g. "artifact.sealed_immutable"
    Message string            // safe for clients; never contains tenant data
    Details map[string]any    // structured, redacted
    Op      string            // operation for the call chain
    Err     error             // wrapped
}

func E(op string, kind Kind, code, msg string, args ...any) *Error
func (e *Error) Unwrap() error
func KindOf(err error) Kind
func HTTPStatus(err error) int     // single mapping point
```

Rules: wrap with `%w` at every boundary, never log-and-return, never expose internal messages. HTTP
responses use RFC 9457 `application/problem+json` with `type`, `title`, `status`, `detail`,
`instance`, `code`, `trace_id`.

### 2.2 Context values

```go
type TenantContext struct {
    TenantID     types.TenantID
    ProjectID    *types.ProjectID
    IsolationMode types.IsolationMode
}
type Principal struct {
    ID types.PrincipalID; Kind PrincipalKind; Subject, Issuer, Display string
    Permissions authz.Set   // bitset
    AuthTime time.Time; AMR []string; BreakGlass bool; OnBehalfOf *types.PrincipalID
}
func WithTenant(ctx, TenantContext) context.Context
func TenantFrom(ctx) (TenantContext, bool)
func PrincipalFrom(ctx) (Principal, bool)
```

Every exported service method takes `ctx` first. Repositories call `db.TenantConn(ctx)` which
refuses to return a connection when `TenantFrom` is absent — a missing tenant context is a
programming error caught at the first query, not a silent cross-tenant read.

### 2.3 Database access & RLS

```go
type DB interface {
    // Tx runs fn in a transaction with app.tenant_id / app.principal_id set for RLS.
    Tx(ctx context.Context, fn func(ctx context.Context, tx Tx) error) error
    // Query obtains a tenant-scoped connection for reads.
    Conn(ctx context.Context) (Conn, error)
}
```

`Tx` performs, on acquire:

```sql
SET LOCAL app.tenant_id    = $1;
SET LOCAL app.principal_id = $2;
SET LOCAL app.break_glass  = $3;
SET LOCAL statement_timeout = '15s';
SET LOCAL idle_in_transaction_session_timeout = '30s';
```

`SET LOCAL` scopes the setting to the transaction, so a pooled connection cannot leak tenant context
to the next borrower. Isolation level: `READ COMMITTED` by default; `REPEATABLE READ` for sealing
and for consistency-score computation.

### 2.4 Transactional outbox

```go
type Outbox interface {
    Append(ctx context.Context, tx db.Tx, evts ...event.Envelope) error
}
```

Relay loop: `SELECT … WHERE published_at IS NULL ORDER BY created_at FOR UPDATE SKIP LOCKED
LIMIT 200`, publish, mark. `SKIP LOCKED` lets N relay replicas run concurrently without contention.
Publish failure leaves rows unpublished; the next pass retries. Duplicate publishes are absorbed by
consumer idempotency.

### 2.5 Canonicalization and hashing

```go
package jcs
func Canonicalize(v any) ([]byte, error)   // RFC 8785
package hash
func Content(v any) (types.ContentHash, error)  // "sha256:<hex>" over jcs.Canonicalize
func Chain(prev types.Hash, payload []byte) types.Hash
```

Property tests assert: key-order independence, unicode normalization stability, number formatting
stability, and round-trip equality across Go and the TypeScript implementation used in the web app
(shared golden vectors in `testdata/jcs/`).

### 2.6 FSM

See `03-state-machines.md §10`. Machines are declared as package-level tables and validated at
`init()`; an invalid table panics at startup rather than at the first transition.

### 2.7 Idempotency

```go
type Store interface {
    Begin(ctx, key string, reqHash [32]byte) (Result, bool /*replay*/, error)
    Complete(ctx, key string, status int, body []byte) error
}
```

Middleware applies to all non-GET routes. Same key + different body hash → `409
idempotency.key_reuse`. Records live 24 h in Postgres (not Redis) so a replay survives a cache flush.

### 2.8 Rate limiting & quotas

Redis token bucket, keys `sf:{tenant}:rl:{dimension}`. Dimensions: per-principal RPS, per-tenant RPS,
per-tenant inference tokens/min, per-tenant concurrent jobs. Responses carry `RateLimit-Limit`,
`RateLimit-Remaining`, `RateLimit-Reset`. Limits are tenant plan attributes.

## 3. Module design — Tenancy

```go
// domain
type Tenant struct {
    ID types.TenantID; Slug, Name string
    Status Status                    // FSM-managed
    IsolationMode types.IsolationMode
    Region string
    Settings Settings
    CreatedBy types.PrincipalID; CreatedAt time.Time
    Version int64                    // optimistic concurrency
}
func (t *Tenant) Rename(name string) error
func NewTenant(slug, name string, mode types.IsolationMode, by types.PrincipalID) (*Tenant, error)

// app ports
type Repository interface {
    Create(ctx, tx db.Tx, *Tenant) error
    GetByID(ctx, types.TenantID) (*Tenant, error)
    GetBySlug(ctx, string) (*Tenant, error)
    List(ctx, ListFilter) (Page[*Tenant], error)
    Update(ctx, tx db.Tx, *Tenant) error   // optimistic on Version
}
type Provisioner interface {   // implemented per isolation mode
    Provision(ctx, *Tenant) error          // schema/bucket prefix/topic/keys
    Deprovision(ctx, *Tenant) error
}
```

`CreateTenant` use case: validate slug → `db.Tx` → insert → audit → outbox(`tenant.created`) →
commit → (async) `Provisioner.Provision` driven by the event, so provisioning failure never leaves a
half-committed tenant row; the tenant stays `PROVISIONING` until the provisioner reports success.

## 4. Module design — Identity

```go
type IdentityProvider interface {          // OIDC today, SAML adapter later
    AuthorizeURL(state, nonce, redirect string, prompt ...string) string
    Exchange(ctx, code, verifier string) (*TokenSet, error)
    Verify(ctx, rawIDToken string) (*Claims, error)
    UserInfo(ctx, accessToken string) (*Claims, error)
    EndSessionURL(idTokenHint, postLogout string) string
    Metadata(ctx) (*ProviderMetadata, error)
}

type Authenticator interface {             // used by middleware
    Authenticate(ctx, r *http.Request) (Principal, error)
}
```

- `oidc.Provider` — discovery, JWKS cache (5 min refresh, 30 s negative cache), `RS256|ES256` only,
  clock skew 60 s, mandatory `aud`/`iss`/`exp`/`nbf`, replay protection on `nonce`.
- `apikey.Authenticator` — `sf_<env>_<keyid>_<secret>`; lookup by `keyid`, compare
  `argon2id(secret)` in constant time, check expiry/revocation, load scoped permission set.
- `devidp` — a **fully functional local OIDC provider** (authorization code + PKCE, JWKS, discovery
  document, seeded users per role) so the whole platform runs offline with real OIDC semantics.
  It is compiled behind the `dev` build tag and refuses to start when `SF_ENV=production`.

JIT provisioning: on first successful login, create the `Principal`, map IdP groups → roles via the
tenant's versioned mapping, emit `principal.authenticated` and `role.assignment.changed`.

## 5. Module design — Authorization

```go
package authz
type Permission uint16              // dense enum, generated from configs/rbac/permissions.yaml
type Set struct{ bits [N]uint64 }   // fixed-size bitset
func (s Set) Has(p Permission) bool
func (s Set) HasAll(ps ...Permission) bool

type Resolver interface {
    PermissionsFor(ctx, principal types.PrincipalID, t types.TenantID, p *types.ProjectID) (Set, error)
}

type Decision struct{ Allowed bool; RuleID, Reason string; Evaluated map[string]any }
type Evaluator interface {          // ABAC layer for the sensitive-action set
    Evaluate(ctx, action Action, res Resource, pr Principal) (Decision, error)
}
```

- `Resolver` caches in Redis for 60 s under `sf:{tenant}:perm:{principal}:{project}`, invalidated by
  `role.assignment.changed` and `tenant.settings.updated`.
- `Evaluator` uses CEL programs compiled once at policy-set load; each rule has a stable `RuleID`
  recorded in the audit record so denials are explainable.
- Route declaration:

```go
r.With(mw.Require(authz.ArtifactApprove), mw.StepUp(15*time.Minute)).
  Post("/projects/{projectID}/artifacts/{artifactID}/versions/{version}:approve", h.Approve)
```

## 6. Module design — Audit

```go
type Record struct {
    ID types.ULID; TenantID types.TenantID; ProjectID *types.ProjectID
    Sequence int64                 // per-tenant, gapless
    Action string                  // "prd.approve"
    Actor Actor; Target Target
    Outcome Outcome                // SUCCESS | DENIED | FAILURE
    Severity Severity
    Attributes map[string]any      // redacted, schema-checked
    RequestID, TraceID string
    OccurredAt time.Time
    PrevHash, RecordHash types.Hash
}

type Writer interface {
    Append(ctx context.Context, tx db.Tx, r *Record) error   // must be in the caller's tx
}
type Verifier interface {
    VerifyChain(ctx, t types.TenantID, from, to int64) (VerifyReport, error)
    Anchor(ctx, t types.TenantID) (AnchorRef, error)
}
```

Chain: `RecordHash = SHA-256(PrevHash ‖ JCS(record minus {RecordHash}))`. `Sequence` is allocated by
`SELECT … FOR UPDATE` on a per-tenant counter row inside the caller's transaction, giving gapless
ordering; the hash chain then makes any later reordering or edit detectable. Hourly `Anchor` writes
the chain head to object storage with object-lock, so an attacker with full DB access still cannot
rewrite history undetectably.

Append-only enforcement: `REVOKE UPDATE, DELETE ON audit_records`, plus a `BEFORE UPDATE OR DELETE`
trigger that raises. Retention and export are read-side concerns.

## 7. Module design — Artifact Graph (Phase 1 core, extended in Phase 4)

```go
type Artifact struct {
    TenantID; ProjectID; ID types.ArtifactID; Type types.ArtifactType
    CurrentVersion int; Status Status; CreatedAt, CreatedBy
}
type Version struct {
    ArtifactID types.ArtifactID; Version int; Status Status
    ContentSchema string; Content json.RawMessage; ContentRef *ContentRef
    ContentHash types.ContentHash
    ParentArtifact, SourceArtifact *Ref
    PreviousVersion *int; ChangeSummary string
    Generator Generator
    ApprovedBy *types.PrincipalID; ApprovedAt *time.Time
    ApprovalComment string; ApprovalEvidence *EvidenceRef
    CreatedBy types.PrincipalID; CreatedAt time.Time
}

type Reader interface {                 // exported via ports; safe for all modules
    Get(ctx, types.ArtifactID) (*Artifact, error)
    GetVersion(ctx, types.ArtifactID, v int) (*Version, error)   // verifies content hash
    Latest(ctx, types.ArtifactID) (*Version, error)
    ListLinks(ctx, LinkFilter) ([]TraceLink, error)
    Traverse(ctx, TraverseSpec) (Paths, error)
}
type Writer interface {                 // NOT exported to sync
    CreateDraft(ctx, tx db.Tx, in NewVersion) (*Version, error)
    UpdateDraft(ctx, tx db.Tx, in DraftPatch) (*Version, error)
    Transition(ctx, tx db.Tx, id types.ArtifactID, v int, ev fsm.Event, args TransitionArgs) (*Version, error)
}
```

`GetVersion` recomputes and compares the content hash on every read; mismatch returns
`KindTampered` and emits `artifact.integrity.violated`.

## 8. HTTP layer

- Router: `chi`. Middleware order is fixed and unit-tested:
  `recover → requestID → otel → logger → securityHeaders → cors → bodyLimit → timeout →
   authn → tenant → ratelimit → authz → idempotency → handler`.
- Timeouts: server read 10 s, write 30 s (300 s on SSE routes), idle 120 s; per-handler
  `context.WithTimeout` default 15 s, overridable per route.
- Body limit 1 MiB default, 25 MiB on upload routes with streaming to object storage.
- Graceful shutdown: SIGTERM → stop accepting → `server.Shutdown(ctx, 25s)` → drain workers → close
  DB/Redis/producer. `terminationGracePeriodSeconds: 40` in K8s, `preStop` sleep 5 s so the LB
  deregisters first.
- SSE: `text/event-stream`, heartbeat every 15 s, per-connection tenant+project scoped subscription,
  connection cap per principal, back-pressure by dropping to a `lag` event rather than buffering.

## 9. Configuration

Precedence: defaults → file (`configs/config.yaml`) → environment (`SF_` prefix) → flags.
Validated at startup with `validate` tags; the process exits non-zero on any invalid or missing
required value. Secrets are **never** in config files: `SecretStore` port resolves
`secret://name#key` references at startup and on rotation.

```yaml
env: development
http: { addr: ":8080", read_timeout: 10s, write_timeout: 30s }
db:   { dsn: secret://sf/db#dsn, max_conns: 25, min_conns: 5 }
redis:{ addr: "redis:6379", tls: false }
objstore: { provider: s3|minio, bucket: sf-content, evidence_bucket: sf-evidence, object_lock: true }
events:  { brokers: ["redpanda:9092"], topic_prefix: "sf." }
auth: { issuer: "https://idp/realms/specforge", audience: "specforge-api", jwks_ttl: 5m,
        tenant_claim: "https://specforge.io/tenant" }
otel: { endpoint: "otel-collector:4317", sample_ratio: 0.1 }
ai:   { gateway_url: "http://gateway:8090", default_provider: simulator }
governance: { four_eyes: true, step_up_max_age: 15m }
```

## 10. Concurrency and consistency

| Situation | Mechanism |
|-----------|-----------|
| Concurrent edits to a draft | Optimistic concurrency on `version_no`; `409` with the current state |
| Concurrent approvals | Conditional update `WHERE status='USER_REVIEW'`; loser gets `409 artifact.not_in_review` |
| Long jobs | Redis lease `sf:{tenant}:lease:{job}` with TTL and fencing token; the token is checked at write time so a resurrected worker cannot overwrite |
| Sequence allocation (audit, artifact version) | `SELECT … FOR UPDATE` on a counter row inside the transaction |
| Cache stampede | Single-flight per key + jittered TTL |
| Graph invalidation | `graph_version` counter per project bumped in the same transaction; cache keys embed it, so invalidation is atomic with the write |

## 11. Testing strategy (Phase 1 scope)

| Layer | Approach |
|-------|----------|
| Domain | Table-driven unit tests; FSM exhaustiveness tests generated from the transition tables |
| Canonicalization/hashing | Golden vectors + property tests (key order, unicode, numbers) |
| Repositories | Real PostgreSQL via testcontainers; migrations applied; **RLS tests that attempt cross-tenant reads and assert zero rows** |
| Application | Fake ports; transaction boundaries asserted; outbox rows asserted per use case |
| Transport | `httptest` with the full middleware chain; authz matrix tests per route per role |
| Audit | Chain verification tests including tamper simulation (mutate a row, assert verification fails) |
| Security | Negative tests: forged tenant claim, missing step-up, service account attempting approval, break-glass without second approver |
| E2E | docker-compose stack, seeded demo tenant, journey script |

Coverage target: ≥ 80% on `domain` and `app`, with mutation-style review of the FSM and authz tests.
Coverage percentage is a signal, not a goal — the FSM, authz and audit tests are the ones that must
be meaningful.
