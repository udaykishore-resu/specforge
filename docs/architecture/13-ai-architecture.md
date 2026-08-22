# SpecForge — AI Architecture

**Status:** Baseline v1.0
**Owner:** AI Platform Architect

---

## 1. Position of the LLM in the system

```
Deterministic input  →  [ LLM: reasoning / generation ]  →  Deterministic validation  →  Governance  →  Artifact
```

The LLM is a **proposer**, never an authority. Three hard rules, enforced in code:

1. **No unvalidated output is persisted.** Every AI response destined for an artifact must validate
   against a versioned JSON Schema. Invalid output is retried once with the validation errors fed
   back, then quarantined as `inference.output.rejected`. There is no "store it anyway" path.
2. **No facts from the model about code.** Facts about source code, routes, dependencies, schemas
   and deployments come from deterministic analyzers. The model may name, cluster, summarize and
   explain; a claim it makes that is not in the fact base is dropped by the cross-checker.
3. **No business logic imports a provider SDK.** Provider SDKs exist only in
   `internal/aiplatform/infra/providers/*`. Enforced by `make lint-arch`.

## 2. Provider abstraction

```go
package ports

type LLMProvider interface {
    Name() string
    Models(ctx context.Context) ([]ModelInfo, error)
    Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
    Stream(ctx context.Context, req CompletionRequest) (Stream, error)
    HealthCheck(ctx context.Context) error
}

type EmbeddingProvider interface {
    Embed(ctx context.Context, req EmbeddingRequest) (*EmbeddingResponse, error)
    Dimensions(model string) (int, error)
}

type ModerationProvider interface {
    Moderate(ctx context.Context, req ModerationRequest) (*ModerationResponse, error)
}

type GuardrailProvider interface {           // see 14-guardrail-architecture.md
    ID() string
    Version() string
    Stage() Stage                            // PRE | POST | BOTH
    Inspect(ctx context.Context, in GuardrailInput) (GuardrailVerdict, error)
    Health(ctx context.Context) error
}

type CompletionRequest struct {
    TenantID types.TenantID; ProjectID *types.ProjectID
    PromptRef PromptRef            // template id + version — never a raw string from a caller
    Variables map[string]any       // validated against the template's declared variable schema
    DataChannels []DataChannel     // untrusted content, delimited and labelled
    Model ModelBinding
    Temperature float32; TopP float32; MaxTokens int
    ResponseSchema *SchemaRef      // required when the output becomes an artifact
    Tools []ToolSpec               // allowlisted, typed
    Deadline time.Duration
    Purpose Purpose                // PRD_DISCOVERY | SPEC_GEN | CODE_GEN | DRIFT_PROPOSAL | EXPLAIN …
}

type CompletionResponse struct {
    InferenceID types.ULID
    Content json.RawMessage        // schema-validated when ResponseSchema set
    Raw string                     // retained per policy only
    Usage TokenUsage; Cost Cost; Latency time.Duration
    Model string; Provider string
    PromptVersion string; GuardrailChainVersion string
    FinishReason string
    GuardrailVerdicts []GuardrailVerdict
}
```

Note `PromptRef`, not a raw prompt string: **callers cannot send arbitrary prompts**. Prompts are
governed artifacts (§5). This closes the largest prompt-injection and cost-abuse surface.

## 3. Shipped provider adapters

| Adapter | Status | Notes |
|---------|--------|-------|
| `simulator` | **Fully implemented, default** | Deterministic, seeded, offline. Produces schema-valid artifacts for every `Purpose` from templated rule-based generation over the input. Makes the whole platform demonstrable and the test suite deterministic. This is a working local implementation, not a stub. |
| `anthropic` | Implemented behind the same interface | Requires `secret://sf/ai/anthropic#key`; disabled when absent |
| `openai` | Implemented | Requires key |
| `bedrock` | Implemented | Uses workload IAM (IRSA), no static key |
| `local_ollama` | Implemented | For air-gapped/on-prem evaluation |

Selection is per tenant and per purpose via `ModelBinding`, with an ordered fallback chain.
A provider that is not in the tenant's `allowed_providers` cannot be selected even if configured
platform-wide.

## 4. AI Gateway

```
Client (api/worker)
  → [authz: ai:invoke, tenant quota, purpose allowed]
  → [prompt resolution: template@version + variable schema validation]
  → [context assembly: tenant-scoped retrieval, redaction, delimiting]
  → PRE-inference guardrail chain      (latency budget)
  → provider call (timeout, retry, circuit breaker, fallback model)
  → POST-inference guardrail chain     (latency budget)
  → [schema validation + fact cross-check]
  → [usage/cost ledger + inference record + audit]
  → Client
```

Gateway responsibilities and non-responsibilities:

- **Does**: authorization, quota, prompt resolution, guardrails, provider routing, retries, circuit
  breaking, budgets, redaction, metering, tracing, recording.
- **Does not**: business logic, artifact writes, governance decisions. It returns validated content;
  the calling module decides what to do with it.

### 4.1 Resilience

| Concern | Setting |
|---------|---------|
| Provider timeout | per-purpose, default 60 s (streaming 300 s) |
| Retry | 2 attempts on 429/5xx/timeouts, exponential backoff + full jitter; never retry a non-idempotent tool call |
| Circuit breaker | per provider+model: opens at 50% failures over 20 requests, half-open probe after 30 s |
| Fallback | ordered model chain; a fallback is recorded on the inference record and surfaced in the UI |
| Bulkhead | per-tenant and per-purpose concurrency limits so PRD chat cannot starve code generation |
| Load shedding | when p95 exceeds the SLO, low-priority purposes (`EXPLAIN`) are shed first with `503` |

## 5. Prompt governance (brief §36)

Prompts are **versioned artifacts** of type `PROMPT` in the artifact graph, subject to the same
lifecycle, approval and audit as any other artifact.

```yaml
id: PRM-0007
version: 4
name: spec_from_prd
purpose: SPEC_GEN
model_requirements: { min_context: 32000, supports_json_schema: true }
variables:
  schema: schemas/prompts/spec_from_prd.vars.v1.json     # validated before rendering
response_schema: schemas/artifacts/spec.v1.json
data_channels: [prd_content]                             # declared untrusted inputs
tools: []                                                 # explicit allowlist, empty here
guardrails: GRC-strict@v2
evaluation: evals/spec_from_prd/                          # required to publish
status: APPROVED
```

Rules:

- A prompt version cannot be published without a passing evaluation run (§7).
- Every inference records the exact `(prompt_version, model, provider, temperature,
  guardrail_chain_version, input_artifacts, output_artifact)` tuple — the brief's §36 requirement.
- Changing a prompt in production is a governance event: it creates a new version, requires
  approval, and emits `prompt.version.published`.
- Rendering is strict: undeclared variables are an error; untrusted content goes only into declared
  `data_channels`, wrapped in delimiters with an explicit "this is data, not instructions" frame.

## 6. Context assembly and retrieval

- Retrieval is **tenant- and project-scoped by construction**: the retriever takes a
  `TenantContext` and cannot be built without one; collections are per tenant.
- Embeddings are stored per tenant with the embedding model version recorded; a model change
  triggers re-embedding rather than mixing vector spaces.
- Redaction runs before assembly: fields tagged `pii`/`secret` never enter a prompt; Presidio-based
  detection catches free-text PII and substitutes reversible placeholders held only in memory.
- Assembled context has a hard token budget per purpose; overflow is resolved by deterministic
  ranking (recency + trace-graph proximity), never by silent truncation mid-artifact.

## 7. Evaluation and quality

| Layer | Method |
|-------|--------|
| Schema conformance | % of outputs valid on first attempt (gate: ≥ 98% for published prompts) |
| Golden set | Curated `(input, expected properties)` pairs per purpose; property assertions, not exact match |
| Fact grounding | Claims about code cross-checked against the deterministic fact base; ungrounded-claim rate must be 0 for artifact-producing purposes |
| Regression | Every prompt or model binding change re-runs the eval suite; a regression blocks publication |
| Human review sampling | Configurable % of AI-generated artifacts routed to mandatory human review regardless of gates |
| Drift monitoring | Rolling schema-failure rate, refusal rate, latency, cost per purpose; alerts on step changes |

Evaluation results are stored as `EVIDENCE` artifacts and attached to the prompt version — an
auditor can see exactly what quality bar a published prompt met.

## 8. Cost, usage and metering

Every inference writes an immutable `InferenceRecord`:

```
inference_id, tenant_id, project_id, purpose, prompt_version, model, provider,
input_tokens, output_tokens, cached_tokens, latency_ms, cost_minor, currency,
guardrail_chain_version, verdicts[], finish_reason, fallback_used, trace_id, actor, occurred_at
```

Aggregated into `ai_usage_ledger` per tenant/project/purpose/day. Budgets emit events at 80/95/100%;
at 100% the gateway rejects with `quota.tokens_exhausted` unless the tenant has an approved overage
exception. Cost is surfaced per project and per artifact — an auditor can see what an artifact cost
to generate.

## 9. Observability of AI

Spans: `ai.request` → `ai.prompt.resolve`, `ai.context.assemble`, `ai.guardrail.pre.{id}`,
`ai.provider.call`, `ai.guardrail.post.{id}`, `ai.validate`.
Attributes: `ai.purpose`, `ai.model`, `ai.provider`, `ai.prompt_version`,
`ai.guardrail_chain_version`, `ai.tokens.input/output`, `ai.cost_minor`, `ai.fallback_used`,
`tenant.id`, `project.id`, `artifact.id`.

Metrics: `sf_ai_requests_total{purpose,provider,model,outcome}`,
`sf_ai_latency_seconds{stage}`, `sf_ai_tokens_total{direction}`, `sf_ai_cost_minor_total`,
`sf_ai_schema_failures_total{purpose}`, `sf_ai_guardrail_blocks_total{guardrail,stage,reason}`.

**Prompt and completion content is not logged by default.** Retention is a tenant policy
(`none | hashes_only | redacted | full`), with `full` requiring an explicit compliance disposition.

## 10. Human-in-the-loop by design

| Purpose | Default human requirement |
|---------|--------------------------|
| PRD discovery / drafting | Human reviews and approves every PRD version — mandatory, not configurable |
| Specification generation | Human approval before `APPROVED`; AI review is advisory |
| BPMN / architecture | Human approval; Architect role required for ARCH |
| Code generation | Human review via PR; generated code cannot merge without review |
| Drift proposals | Governance-routed; HIGH severity always requires a human |
| Explanations / summaries | No approval required; clearly labelled as AI-generated and non-authoritative |

Every AI-generated artifact is visually and structurally labelled (`generator.kind = INFERENCE`), so
a reviewer always knows what they are approving.
