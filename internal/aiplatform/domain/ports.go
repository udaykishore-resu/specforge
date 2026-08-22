// Package domain defines the AI platform's contracts.
//
// The central rule of this package: business logic never imports a provider
// SDK. Every consumer depends on these interfaces, and provider adapters live
// under infra/providers. That is what keeps a model swap from becoming a
// refactor, and what makes it possible to run the whole platform offline.
//
// The second rule: callers cannot send arbitrary prompt text. A CompletionRequest
// carries a PromptRef — a governed, versioned prompt artifact — plus validated
// variables and explicitly delimited untrusted data. That closes the largest
// prompt-injection and cost-abuse surface at the type level.
package domain

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/specforge/specforge/internal/platform/types"
)

// Purpose classifies what an inference is for. Budgets, guardrail chains,
// prompt allowlists and load-shedding priority are all keyed on it.
type Purpose string

const (
	PurposePRDDiscovery   Purpose = "PRD_DISCOVERY"
	PurposePRDDraft       Purpose = "PRD_DRAFT"
	PurposeSpecGen        Purpose = "SPEC_GEN"
	PurposeModelGen       Purpose = "MODEL_GEN"
	PurposeCodeGen        Purpose = "CODE_GEN"
	PurposeDriftProposal  Purpose = "DRIFT_PROPOSAL"
	PurposeReverseNarrate Purpose = "REVERSE_NARRATE"
	PurposeExplain        Purpose = "EXPLAIN"
)

// Valid reports whether p is a known purpose.
func (p Purpose) Valid() bool {
	switch p {
	case PurposePRDDiscovery, PurposePRDDraft, PurposeSpecGen, PurposeModelGen,
		PurposeCodeGen, PurposeDriftProposal, PurposeReverseNarrate, PurposeExplain:
		return true
	}
	return false
}

// Authoritative reports whether output for this purpose can become a governed
// artifact. Authoritative purposes must declare a response schema and are always
// subject to human approval.
func (p Purpose) Authoritative() bool { return p != PurposeExplain }

// PromptRef names a governed prompt artifact and version.
type PromptRef struct {
	ID      string `json:"id"`      // e.g. "PRM-0007"
	Version int    `json:"version"` // e.g. 4
}

func (p PromptRef) String() string { return fmt.Sprintf("%s@v%d", p.ID, p.Version) }
func (p PromptRef) Zero() bool     { return p.ID == "" }

// DataChannel carries untrusted content into a prompt.
//
// Content arriving here is framed as data, never as instructions. The label is
// rendered into the prompt so the model is told explicitly which region is
// untrusted, and the guardrail chain scans these regions for injection attempts.
type DataChannel struct {
	Label   string `json:"label"`
	Content string `json:"content"`
	// Source records where the content came from, for the inference record.
	Source string `json:"source,omitempty"`
}

// ModelBinding pins a model and its fallbacks.
type ModelBinding struct {
	ID       string   `json:"id"`
	Provider string   `json:"provider"`
	Model    string   `json:"model"`
	Fallback []string `json:"fallback,omitempty"`
}

// CompletionRequest is a governed inference request.
type CompletionRequest struct {
	TenantID  types.TenantID
	ProjectID *types.ProjectID
	Purpose   Purpose
	Prompt    PromptRef
	Variables map[string]any
	Channels  []DataChannel
	Binding   ModelBinding
	// ResponseSchema is required whenever the output becomes an artifact.
	ResponseSchema string
	Temperature    float32
	MaxTokens      int
	Deadline       time.Duration
	// InputArtifacts records what the inference was derived from, so the output
	// artifact's provenance is complete.
	InputArtifacts []types.ArtifactRef
	// Actor is the principal on whose behalf the inference runs. Tool
	// authorization re-checks against this, not against the agent.
	Actor types.PrincipalID
}

// Validate checks a request before any provider is contacted.
func (r CompletionRequest) Validate() error {
	if r.TenantID.Empty() {
		return fmt.Errorf("aiplatform: a tenant is required")
	}
	if !r.Purpose.Valid() {
		return fmt.Errorf("aiplatform: purpose %q is not recognised", r.Purpose)
	}
	if r.Prompt.Zero() {
		return fmt.Errorf("aiplatform: a governed prompt reference is required; " +
			"raw prompt text is not accepted")
	}
	if r.Purpose.Authoritative() && r.ResponseSchema == "" {
		// Without a schema there is nothing to validate the output against, and
		// unvalidated model output must never reach the artifact graph.
		return fmt.Errorf("aiplatform: purpose %s produces governed artifacts and "+
			"must declare a response schema", r.Purpose)
	}
	return nil
}

// TokenUsage records consumption.
type TokenUsage struct {
	Input  int `json:"input"`
	Output int `json:"output"`
	Cached int `json:"cached,omitempty"`
}

// Cost is money in minor units, never a float.
type Cost struct {
	Minor    int64  `json:"minor"`
	Currency string `json:"currency"`
}

// CompletionResponse is a validated inference result.
type CompletionResponse struct {
	InferenceID string          `json:"inference_id"`
	Content     json.RawMessage `json:"content"`
	Usage       TokenUsage      `json:"usage"`
	Cost        Cost            `json:"cost"`
	Latency     time.Duration   `json:"latency"`
	Model       string          `json:"model"`
	Provider    string          `json:"provider"`
	// PromptVersion, GuardrailChainVersion and Model together are what an
	// artifact's provenance records, so a past generation can be explained.
	PromptVersion         string    `json:"prompt_version"`
	GuardrailChainVersion string    `json:"guardrail_chain_version"`
	FinishReason          string    `json:"finish_reason"`
	FallbackUsed          bool      `json:"fallback_used"`
	Verdicts              []Verdict `json:"guardrail_verdicts,omitempty"`
	// Grounding lists the claims the response makes and whether each was
	// confirmed against the deterministic fact base.
	Grounding []GroundingClaim `json:"grounding,omitempty"`
}

// GroundingClaim records whether a factual assertion was corroborated.
type GroundingClaim struct {
	Claim     string `json:"claim"`
	Grounded  bool   `json:"grounded"`
	Reference string `json:"reference,omitempty"`
}

// LLMProvider generates completions.
type LLMProvider interface {
	Name() string
	Models(ctx context.Context) ([]ModelInfo, error)
	Complete(ctx context.Context, req CompletionRequest, rendered RenderedPrompt) (*CompletionResponse, error)
	HealthCheck(ctx context.Context) error
}

// ModelInfo describes a model a provider offers.
type ModelInfo struct {
	Name            string `json:"name"`
	ContextTokens   int    `json:"context_tokens"`
	SupportsSchema  bool   `json:"supports_json_schema"`
	InputCostMinor  int64  `json:"input_cost_minor_per_mtok"`
	OutputCostMinor int64  `json:"output_cost_minor_per_mtok"`
}

// EmbeddingProvider produces vectors.
type EmbeddingProvider interface {
	Name() string
	Embed(ctx context.Context, tenantID types.TenantID, model string, inputs []string) ([][]float32, error)
	Dimensions(model string) (int, error)
}

// ModerationProvider classifies content safety.
type ModerationProvider interface {
	Name() string
	Moderate(ctx context.Context, content string) (Verdict, error)
}

// RenderedPrompt is the output of prompt resolution: system text, the user
// instruction, and the untrusted data channels kept separate.
type RenderedPrompt struct {
	System       string        `json:"system"`
	Instruction  string        `json:"instruction"`
	Channels     []DataChannel `json:"channels"`
	ResponseHint string        `json:"response_hint,omitempty"`
}

// ---------------------------------------------------------------------------
// Guardrails
// ---------------------------------------------------------------------------

// Stage is where in the pipeline a guardrail runs.
type Stage string

const (
	StagePre  Stage = "PRE"
	StagePost Stage = "POST"
)

// Action is a guardrail's decision.
type Action string

const (
	ActionAllow  Action = "ALLOW"
	ActionRedact Action = "REDACT"
	ActionBlock  Action = "BLOCK"
	ActionFlag   Action = "FLAG"
)

// Precedence orders actions: the strictest wins when verdicts are combined.
func (a Action) Precedence() int {
	switch a {
	case ActionBlock:
		return 4
	case ActionRedact:
		return 3
	case ActionFlag:
		return 2
	default:
		return 1
	}
}

// Verdict is a guardrail's result.
type Verdict struct {
	GuardrailID      string        `json:"guardrail_id"`
	GuardrailVersion string        `json:"guardrail_version"`
	Action           Action        `json:"action"`
	ReasonCode       string        `json:"reason_code,omitempty"`
	Score            float64       `json:"score,omitempty"`
	Findings         []Finding     `json:"findings,omitempty"`
	Redacted         string        `json:"-"`
	Latency          time.Duration `json:"latency_ms"`
}

// Finding is one detection within a verdict.
type Finding struct {
	Category   string  `json:"category"`
	EntityType string  `json:"entity_type,omitempty"`
	Start      int     `json:"start,omitempty"`
	End        int     `json:"end,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

// GuardrailInput is what a guardrail inspects.
type GuardrailInput struct {
	InferenceID string
	Stage       Stage
	Purpose     Purpose
	Content     string
	// Channels marks which regions of Content are untrusted, so an injection
	// guardrail can weight them differently from the platform's own instructions.
	Channels []DataChannel
	Config   map[string]any
	BudgetMS int
}

// Guardrail is the standard interface every control implements, first-party or
// customer-supplied. The gateway knows nothing about a guardrail's internals.
type Guardrail interface {
	Describe() Descriptor
	Inspect(ctx context.Context, in GuardrailInput) (Verdict, error)
	Health(ctx context.Context) error
}

// Descriptor advertises a guardrail's capabilities.
type Descriptor struct {
	ID                string   `json:"id"`
	Version           string   `json:"version"`
	Stage             Stage    `json:"stage"`
	Categories        []string `json:"categories"`
	SupportsRedaction bool     `json:"supports_redaction"`
	TypicalLatencyMS  int      `json:"typical_latency_ms"`
}

// FailureMode decides what happens when a guardrail cannot produce a verdict.
type FailureMode string

const (
	// FailClosed blocks the inference. The default for anything handling PII,
	// secrets or safety.
	FailClosed FailureMode = "fail_closed"
	// FailOpen allows it with a flag. Permitted only for advisory guardrails and
	// only with a recorded Design Authority disposition.
	FailOpen FailureMode = "fail_open"
)

// GuardrailStep is one guardrail's placement in a chain.
type GuardrailStep struct {
	GuardrailID string        `json:"guardrail"`
	Timeout     time.Duration `json:"timeout"`
	MaxLatency  time.Duration `json:"max_latency"`
	OnFinding   Action        `json:"on_finding"`
	FailureMode FailureMode   `json:"failure_mode"`
	Required    bool          `json:"required"`
	// DispositionID is mandatory when FailureMode is FailOpen on a safety,
	// PII or secrets guardrail.
	DispositionID string `json:"disposition_id,omitempty"`
}

// GuardrailChain is a versioned, governed configuration.
type GuardrailChain struct {
	ID          string          `json:"id"`
	Version     int             `json:"version"`
	TotalPreMS  int             `json:"total_pre_ms"`
	TotalPostMS int             `json:"total_post_ms"`
	Pre         []GuardrailStep `json:"pre"`
	Post        []GuardrailStep `json:"post"`
}

func (c GuardrailChain) String() string { return fmt.Sprintf("%s@v%d", c.ID, c.Version) }

// safetyCategories are the guardrail categories that may never fail open
// without an explicit, recorded governance decision.
var safetyCategories = map[string]bool{
	"pii": true, "secrets": true, "safety": true, "prompt_injection": true,
}

// Validate checks a chain before it is loaded.
//
// The important rule: a guardrail in a safety category cannot be set to fail
// open without a disposition. A configuration mistake must not be able to
// silently weaken a safety control.
func (c GuardrailChain) Validate(catalogue map[string]Descriptor) error {
	if c.ID == "" {
		return fmt.Errorf("aiplatform: a guardrail chain needs an identifier")
	}
	if c.TotalPreMS <= 0 || c.TotalPostMS <= 0 {
		return fmt.Errorf("aiplatform: chain %s must declare latency budgets", c.ID)
	}

	check := func(steps []GuardrailStep, stage Stage) error {
		for _, step := range steps {
			d, known := catalogue[step.GuardrailID]
			if !known {
				return fmt.Errorf("aiplatform: chain %s references unknown guardrail %q",
					c.ID, step.GuardrailID)
			}
			if d.Stage != stage && d.Stage != "" {
				return fmt.Errorf("aiplatform: guardrail %s cannot run at stage %s",
					step.GuardrailID, stage)
			}
			if step.Timeout <= 0 {
				return fmt.Errorf("aiplatform: guardrail %s declares no timeout", step.GuardrailID)
			}
			if step.FailureMode == FailOpen && step.DispositionID == "" {
				for _, cat := range d.Categories {
					if safetyCategories[cat] {
						return fmt.Errorf(
							"aiplatform: guardrail %s handles %s and cannot fail open "+
								"without a recorded Design Authority disposition",
							step.GuardrailID, cat)
					}
				}
			}
		}
		return nil
	}

	if err := check(c.Pre, StagePre); err != nil {
		return err
	}
	return check(c.Post, StagePost)
}

// InferenceRecord is the immutable meter and provenance entry for one inference.
type InferenceRecord struct {
	InferenceID           string              `json:"inference_id"`
	TenantID              types.TenantID      `json:"tenant_id"`
	ProjectID             *types.ProjectID    `json:"project_id,omitempty"`
	Purpose               Purpose             `json:"purpose"`
	PromptVersion         string              `json:"prompt_version"`
	Model                 string              `json:"model"`
	Provider              string              `json:"provider"`
	GuardrailChainVersion string              `json:"guardrail_chain_version"`
	Usage                 TokenUsage          `json:"usage"`
	Cost                  Cost                `json:"cost"`
	LatencyMS             int64               `json:"latency_ms"`
	FinishReason          string              `json:"finish_reason"`
	FallbackUsed          bool                `json:"fallback_used"`
	Outcome               string              `json:"outcome"` // COMPLETED | BLOCKED | FAILED
	BlockedBy             string              `json:"blocked_by,omitempty"`
	Verdicts              []Verdict           `json:"verdicts,omitempty"`
	InputArtifacts        []types.ArtifactRef `json:"input_artifacts,omitempty"`
	Actor                 types.PrincipalID   `json:"actor"`
	TraceID               string              `json:"trace_id,omitempty"`
	OccurredAt            time.Time           `json:"occurred_at"`
}
