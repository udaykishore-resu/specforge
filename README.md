# SpecForge

A governed, traceable, AI-native platform for spec-driven software engineering.

SpecForge maintains a bidirectionally traceable graph running from business
intent through PRDs, specifications, process models, architecture, APIs, code,
tests and deployments — and it can answer, from data rather than from memory:

- **Why does this code exist?** — walk upstream to the approved requirement.
- **What implements this requirement?** — walk downstream to code and tests.
- **What breaks if this changes?** — a deterministic impact set, not a guess.
- **Who approved this, when, and on what evidence?** — a write-once evidence
  document and a hash-chained audit record.
- **Is what is running still what was approved?** — content hashes compared
  against a published anchor.

> **The platform is not an LLM wrapper.** Models propose. Deterministic systems
> parse, validate, version, authorize and record. The approved artifact model
> and the governance engine are authoritative, and no model output becomes fact
> without passing schema validation, policy gates and a human approval that is
> itself recorded as evidence.

---

## Quick start

Requirements: Docker with Compose, and Make. Go 1.24 and Node 22 if you intend
to run things outside containers.

```bash
make dev
```

That starts PostgreSQL, Redis, Redpanda, MinIO (with object lock), the OTel
collector, Jaeger, Prometheus and Grafana; applies the migrations; and seeds a
worked example — an approved requirement, a specification derived from it, an
accepted trace link between them, and a verifiable audit chain.

| Service       | URL                                                        |
| ------------- | ---------------------------------------------------------- |
| Console       | http://localhost:3000                                      |
| API           | http://localhost:8080                                      |
| Dev identity  | http://localhost:8081/.well-known/openid-configuration     |
| Grafana       | http://localhost:3001                                      |
| Jaeger        | http://localhost:16686                                     |
| MinIO console | http://localhost:9001                                      |

Sign in as any of the twelve seeded roles. Start as **Analyst** to see a draft
move through review, then as **Owner** to approve it — the platform will refuse
to let the same person do both.

To check that all six are actually working, and that the guarantees behind them
hold:

```bash
make smoke
```

It walks a real sign-in, calls the API as four different roles, confirms the
refusals are refusals, verifies the audit chain, and checks that traces and
metrics arrived. [docs/testing-the-local-stack.md](docs/testing-the-local-stack.md)
explains each check and how to run it by hand.

## Verify it yourself

The platform is built so that its claims can be checked without trusting it.

```bash
# Recompute every audit hash and compare against the published anchor.
make verify-audit TENANT=<tenant-id>

# Verify an exported approval offline. This never contacts the platform.
specforge-cli verify-evidence --file evidence.json --digest sha256:...
```

```bash
make check              # formatting, vet, route lint, unit and contract tests
make test-integration   # the full forward journey against PostgreSQL
make test-isolation     # 28 database invariants: RLS, immutability, audit trail
```

`make test-isolation` is the one to run if you only run one. It asserts, in
SQL, that a tenant cannot read another tenant's rows, that an approved version
cannot be modified or deleted, that an audit record cannot be updated even by
the table owner, and that an API key cannot hold an approval permission.

---

## How it is built

### A modular monolith with enforced boundaries

One deployable, several bounded contexts, each with `domain` / `app` / `infra` /
`transport` layers. Cross-module calls go through `ports` only. The
architecture is ready to split into services when there is a reason to; it does
not pay the cost of distribution before then.

```
internal/
├── platform/       cross-cutting: db, authn, authz, jcs, hash, fsm, obs, outbox
├── tenancy/        tenants and projects
├── identity/       principals, roles, API keys, IdP mapping
├── artifactgraph/  the canonical artifact model and traceability
├── audit/          the hash-chained, append-only trail
├── aiplatform/     LLM ports, guardrails, and a deterministic simulator
└── server/         HTTP transport, middleware, route table
```

### Content addressing that means something

Every artifact version is hashed as
`SHA-256(JCS(envelope))` — RFC 8785 canonical JSON, so the hash is reproducible
in any language. The envelope deliberately excludes `status`, the approval
fields and trace links, which gives the property that matters: **the hash of an
approved version is the hash of exactly the bytes that were reviewed**, and it
does not change as the version moves through its lifecycle. `SealApproval`
asserts this rather than assuming it.

Reads verify the hash before returning content and fail closed on a mismatch.

### Immutability enforced twice

An approved version is sealed in the domain, and the database refuses to modify
it independently — a trigger compares the row minus its lifecycle columns and
raises. Partial unique indexes enforce one approved version per artifact; check
constraints enforce that an approval has evidence and that an LLM-proposed
trace link cannot be accepted without a recorded human disposition.

Authorization is not enforced in one place either: an API key that tried to
hold an approval permission is rejected by the application *and* by a `CHECK`
constraint.

### Tenant isolation in the database

Row-level security with `FORCE ROW LEVEL SECURITY`, keyed on a session variable
set with `SET LOCAL` inside each transaction. A missing tenant context returns
zero rows rather than everything. The isolation tests prove that the setting
does not leak between pooled transactions.

### No dual writes

State changes and their domain events commit in the same transaction, through a
transactional outbox. A relay publishes at least once; consumers are idempotent
against a `processed_events` table. An operation that failed to record its
audit entry could not have succeeded, because the audit write is in the same
transaction as the change it describes.

### An audit trail built to be doubted

Per-tenant, gapless sequences. Each record hashes its own content plus its
predecessor's hash. Verification checks all three properties — record hashes,
linkage, and the absence of gaps — because checking only hashes would miss the
wholesale deletion of a contiguous block.

Internal consistency alone proves little: an attacker with write access could
rewrite every record and recompute every hash. So the worker publishes chain
anchors to write-once, object-locked storage, and verification compares against
the last anchor. The report says which anchor it used, so nobody mistakes the
weaker claim for the stronger one.

### The approval path

The most consequential code path in the platform, ordered deliberately:

1. Governance gates evaluate. A blocking gate stops the request before any
   evidence is written.
2. Authorization, including four-eyes (an approver may not have authored any
   version of the artifact) and step-up authentication freshness.
3. Canonical content and the evidence document are written to write-once
   storage.
4. One transaction: supersede the prior approved version, seal this one, update
   the artifact head, bump the project graph version, chain an audit record,
   and write the domain event to the outbox.

Evidence is written before the row is sealed, so a crash leaves an orphaned,
content-addressed evidence object — harmless — rather than an approval with no
evidence behind it.

### The console holds the token, the browser does not

The Next.js console is a server-rendered confidential client. The browser
receives an AES-256-GCM encrypted session cookie; the access token stays on the
server and is attached to API calls there. An XSS on a page cannot exfiltrate a
bearer token that was never sent to the page.

Authentication is the authorization-code flow with PKCE (S256), with the state,
nonce and verifier held in a single-use encrypted cookie. Only asymmetric token
signatures are accepted — `none` and the HMAC family are rejected outright.

---

## Zero third-party Go dependencies

`go.mod` has no `require` block. Everything is the standard library, including
a PostgreSQL wire-protocol driver, a Redis client, a Prometheus text-format
registry, W3C trace context and an OTLP/HTTP exporter, and an RFC 8785
canonicalizer.

This began as a constraint of the build environment and became a deliberate
choice worth keeping for a platform whose job is provenance: every line that
handles a tenant's specifications is in this repository and reviewable.
`make lint-deps` fails the build if a dependency appears, so adding one is a
decision somebody makes on purpose.

The driver is confined to `internal/platform/db/pgwire` behind `database/sql`.
Swapping in pgx is a one-file change behind a build tag.

---

## Repository layout

```
.
├── api/openapi/          the API contract, checked against the router by a test
├── cmd/                  specforge-api, -worker, -migrate, -cli
├── deploy/
│   ├── docker/           Dockerfiles, compose stack, observability config
│   ├── helm/             the chart, with preconditions that refuse unsafe values
│   └── terraform/        VPC, Aurora, S3 with object lock, EKS
├── docs/
│   ├── architecture/     26 documents: domain model, HLD, LLD, threat model, DR
│   └── runbooks/         operational and governance runbooks
├── internal/             the platform (see above)
├── migrations/           SQL, applied in order, verified against PostgreSQL 16
├── test/
│   ├── contract/         the OpenAPI document against the live route table
│   ├── integration/      the forward journey, four-eyes, tenancy, tampering
│   └── isolation/        28 database invariants as SQL assertions
├── tools/lintroutes/     fails the build on a route with no permission
└── web/                  the Next.js console
```

## Documentation

Start with these three, in order:

1. [`docs/architecture/01-domain-model.md`](docs/architecture/01-domain-model.md)
   — ubiquitous language, bounded contexts, aggregates and their invariants.
2. [`docs/architecture/02-canonical-artifact-model.md`](docs/architecture/02-canonical-artifact-model.md)
   — the constitutional document. What is hashed, what is not, and why.
3. [`docs/architecture/05-authorization-model.md`](docs/architecture/05-authorization-model.md)
   — twelve roles, eight enforcement layers, and the separation-of-duties rules.

Then [`03-state-machines.md`](docs/architecture/03-state-machines.md),
[`04-event-model.md`](docs/architecture/04-event-model.md),
[`06-synchronization-strategy.md`](docs/architecture/06-synchronization-strategy.md),
the [threat model](docs/architecture/21-threat-model.md), and the
[operational runbook](docs/runbooks/operational-runbook.md).

For working with a running stack:
[testing the local stack](docs/testing-the-local-stack.md).

## Where the AI sits

`internal/aiplatform` defines the ports — completion, embedding, moderation,
guardrails — and ships a deterministic local simulator that implements every
one of the eight prompt purposes. Real providers are adapters behind the same
interface.

Three properties hold regardless of which provider is configured:

- A completion request carries a **prompt reference**, not raw text, so every
  generation is reproducible from a versioned prompt.
- Generated content is validated against a schema before it can enter the graph,
  and carries the model, prompt version and guardrail chain version that
  produced it.
- A model-proposed trace link is created in `PROPOSED` and **cannot** reach
  `ACCEPTED` without a recorded human disposition — enforced by a database
  constraint, not only by application code.

## Status

Phase 1 (foundation) is complete and verified: repository, authentication,
tenants, projects, the artifact graph, the audit trail, and the console shell.
The implementation plan for phases 2–12 is in
[`docs/architecture/20-implementation-plan.md`](docs/architecture/20-implementation-plan.md).

## License

Proprietary.
