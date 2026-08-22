# SpecForge — Repository Structure

**Status:** Baseline v1.0

```
specforge/
├── README.md                      Quick start, architecture map
├── Makefile                       The build contract (CI calls only make targets)
├── go.mod / go.sum
├── docker-compose.yml             Full local stack
├── .golangci.yml  .gitleaks.toml  .editorconfig  .gitignore
│
├── cmd/
│   ├── specforge-api/             Control-plane HTTP/gRPC server
│   ├── specforge-worker/          Async consumers & schedulers (--roles=…)
│   ├── specforge-gateway/         AI Gateway
│   ├── specforge-migrate/         Migration runner (advisory-locked)
│   └── specforge-cli/             Admin/dev CLI: seed, verify-audit, trace, export
│
├── internal/
│   ├── platform/                  Shared infrastructure — no domain knowledge
│   │   ├── config/ log/ otel/ errors/ httpx/ id/ jcs/ hash/ fsm/ validate/ ptr/
│   │   ├── db/                    pgx pool, Tx with RLS session, health
│   │   ├── outbox/ cache/ objstore/ eventbus/
│   │   ├── authn/ authz/ ratelimit/ idempotency/ schema/ secrets/
│   │   └── adapters/{aws,local}/  Cloud-specific implementations of ports
│   │
│   ├── tenancy/       identity/       audit/        artifactgraph/
│   ├── prd/           spec/           model/        codegen/
│   ├── reverse/       sync/           governance/   delivery/
│   ├── runtime/       compliance/     aiplatform/
│   │     each: domain/ app/ infra/ transport/ ports/
│   │
│   └── server/                    Wiring: router, middleware chain, module registry, DI
│
├── api/
│   ├── openapi/specforge.v1.yaml  Source of truth for the REST surface
│   └── proto/                     Internal gRPC contracts (+ guardrail.proto)
│
├── schemas/
│   ├── artifacts/                 artifact.v1, prd.v1, spec.v1, requirement.v1, bpmn.v1, c4.v1…
│   ├── events/                    One schema per event type, versioned
│   ├── policies/                  Policy set + rule schemas
│   └── prompts/                   Prompt template + variable schemas
│
├── migrations/                    0001_…sql … forward-only
│
├── web/                           Next.js 15 app
│   ├── app/                       App Router: (auth), dashboard, tenants, projects,
│   │                              prd-studio, specifications, bpmn, architecture, code,
│   │                              repositories, pipelines, deployments, kubernetes,
│   │                              governance, compliance, ai-guardrails, audit, settings
│   ├── components/                ui/ (shadcn), artifact-explorer/, traceability-graph/,
│   │                              prd-editor/, diff-viewer/, governance/, charts/
│   ├── lib/                       api client (generated from OpenAPI), auth (BFF), jcs, hooks
│   └── e2e/                       Playwright
│
├── deploy/
│   ├── docker/                    Dockerfiles (api, worker, gateway, web, guardrails)
│   ├── helm/specforge/            Chart
│   ├── k8s/                       Raw manifests for kind/dev
│   └── terraform/
│       ├── modules/{network,eks,rds,redis,msk,s3,kms,iam,observability}/
│       └── envs/{dev,staging,prod}/
│
├── ci/
│   ├── github/                    Reusable workflow fragments
│   └── Jenkinsfile
│
├── test/
│   ├── integration/               testcontainers-backed
│   ├── isolation/                 Cross-tenant isolation suite (release blocker)
│   ├── contract/                  Provider/consumer contract tests
│   ├── e2e/                       Journey scripts
│   └── fixtures/                  Golden artifacts, JCS vectors, corpora
│
├── seed/                          Demo tenant, project, PRD, specs, repo, pipeline data
├── evals/                         Prompt evaluation suites
└── docs/
    ├── architecture/00-25…        This documentation set
    ├── adr/                       Architecture Decision Records
    ├── runbooks/                  Operational + governance runbooks
    ├── requirements/register.yaml Requirement register (self-hosted traceability)
    └── acceptance/journey.md      Executable acceptance script
```

## Enforced boundaries

`make lint-arch` fails the build on:

1. `*/domain` importing anything but stdlib, `platform/types`, `platform/errors`, `platform/fsm`.
2. Cross-module imports that are not `<module>/ports`.
3. `sync/*` importing `artifactgraph/ports.Writer`.
4. Any package outside `aiplatform/infra/providers` importing an LLM provider SDK.
5. `platform/*` importing any domain module (dependency inversion).

## The Makefile is the contract

CI, Jenkins and local development all invoke the same targets, so behaviour cannot drift between
them:

```
make dev            # docker-compose up + migrate + seed + run api/worker/gateway/web
make build test     # build all binaries; unit tests with race detector
make test-integration test-isolation test-e2e
make lint lint-arch lint-routes lint-sql
make migrate seed
make openapi generate schemas   # codegen from OpenAPI/JSON Schema, drift-checked
make docker helm-lint tf-validate
make verify-audit trace-verify  # audit chain + traceability annotation verification
```
