// Package providers holds the LLM provider adapters. This is the only place in
// the codebase permitted to depend on a provider SDK.
package providers

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"time"

	"github.com/specforge/specforge/internal/aiplatform/domain"
	"github.com/specforge/specforge/internal/platform/id"
)

// Simulator is a fully functional offline provider.
//
// It is not a stub and not a mock. It produces schema-valid output for every
// purpose by applying deterministic transformation rules to its input, which
// gives the platform three properties that matter:
//
//   - The entire product journey — discovery, PRD, specifications, models, code
//     generation, drift proposals — is demonstrable with no network access and
//     no API key.
//   - Tests are deterministic. The same input always produces the same output,
//     so a generation regression is a real diff rather than model variance.
//   - The governance path is exercised for real. Output still goes through
//     schema validation, guardrails, gates and human approval, because the
//     simulator's output is treated exactly like any other model's.
//
// What it does not do is reason. It restructures and paraphrases its input. That
// is the honest boundary, and it is why the platform's value does not depend on
// which provider is configured.
type Simulator struct {
	name string
	// latency simulates provider round-trip time so that timeout, budget and
	// circuit-breaker behaviour can be exercised locally.
	latency time.Duration
}

var _ domain.LLMProvider = (*Simulator)(nil)

// NewSimulator builds the offline provider.
func NewSimulator(latency time.Duration) *Simulator {
	if latency < 0 {
		latency = 0
	}
	return &Simulator{name: "simulator", latency: latency}
}

func (s *Simulator) Name() string { return s.name }

func (s *Simulator) Models(context.Context) ([]domain.ModelInfo, error) {
	return []domain.ModelInfo{{
		Name: "sim-reasoner-v1", ContextTokens: 128_000, SupportsSchema: true,
		InputCostMinor: 0, OutputCostMinor: 0,
	}}, nil
}

func (s *Simulator) HealthCheck(context.Context) error { return nil }

// Complete produces deterministic, schema-shaped output for the request's purpose.
func (s *Simulator) Complete(ctx context.Context, req domain.CompletionRequest,
	rendered domain.RenderedPrompt) (*domain.CompletionResponse, error) {

	start := time.Now()

	if s.latency > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(s.latency):
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// The seed is derived from the request, so identical input yields identical
	// output across runs, processes and machines.
	seed := seedOf(req, rendered)

	content, err := s.generate(req, rendered, seed)
	if err != nil {
		return nil, err
	}

	raw, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("simulator: encoding generated content: %w", err)
	}

	inputTokens := estimateTokens(rendered)
	outputTokens := len(raw) / 4

	return &domain.CompletionResponse{
		InferenceID:   "inf_" + id.NewToken(10),
		Content:       raw,
		Usage:         domain.TokenUsage{Input: inputTokens, Output: outputTokens},
		Cost:          domain.Cost{Minor: 0, Currency: "USD"},
		Latency:       time.Since(start),
		Model:         req.Binding.Model,
		Provider:      s.name,
		PromptVersion: req.Prompt.String(),
		FinishReason:  "stop",
		Grounding:     groundingFor(req, content),
	}, nil
}

// generate dispatches on purpose. Each branch emits the shape the corresponding
// artifact schema requires, so the output validates without special-casing.
func (s *Simulator) generate(req domain.CompletionRequest,
	rendered domain.RenderedPrompt, seed uint64) (map[string]any, error) {

	source := channelText(rendered.Channels)
	subject := subjectOf(req, rendered, source)

	switch req.Purpose {
	case domain.PurposePRDDiscovery:
		return map[string]any{
			"questions": discoveryQuestions(subject),
			"dimensions_covered": []string{
				"actors", "business_goals", "functional_requirements",
				"non_functional_requirements", "business_rules", "integrations",
				"security", "compliance", "availability", "scalability",
				"observability", "disaster_recovery",
			},
		}, nil

	case domain.PurposePRDDraft:
		return map[string]any{
			"title":                       subject,
			"summary":                     "Draft product requirements for " + subject + ", derived from the discovery conversation.",
			"actors":                      extractActors(source),
			"goals":                       extractGoals(source),
			"functional_requirements":     extractRequirements(source, "FR"),
			"non_functional_requirements": defaultNFRs(),
			"business_rules":              extractRules(source),
			"security_requirements":       defaultSecurityRequirements(),
			"compliance_requirements":     []string{"Retain approval evidence for seven years."},
			"open_questions":              openQuestions(source),
			"assumptions":                 []string{"Existing identity provider supports OIDC."},
		}, nil

	case domain.PurposeSpecGen:
		return map[string]any{
			"title": subject,
			"type":  "FUNCTIONAL",
			"given": []string{"a signed-in user with the required role"},
			"when":  []string{"they perform " + strings.ToLower(subject)},
			"then":  []string{"the action succeeds and is recorded in the audit trail"},
			"acceptance_criteria": []map[string]any{
				{"id": "AC-1", "text": "The action is refused when the caller lacks the permission."},
				{"id": "AC-2", "text": "The action is recorded with actor, target and outcome."},
			},
			"business_rules": extractRules(source),
			"security_rules": []string{"The operation requires an authenticated principal."},
			"observability":  []string{"Emit a span and a counter for the operation."},
			"failure_conditions": []string{
				"The dependency is unavailable.",
				"The caller's authentication has expired.",
			},
		}, nil

	case domain.PurposeModelGen:
		return map[string]any{
			"process_name": subject,
			"tasks":        []string{"Receive request", "Validate", "Authorize", "Execute", "Record outcome"},
			"gateways":     []map[string]any{{"id": "gw-1", "type": "exclusive", "condition": "authorized?"}},
			"events":       []map[string]any{{"id": "start", "type": "start"}, {"id": "end", "type": "end"}},
		}, nil

	case domain.PurposeCodeGen:
		return map[string]any{
			"package": "service",
			"files": []map[string]any{{
				"path": "internal/service/handler.go",
				// Generated code carries traceability annotations, so the link
				// back to the specification survives outside the platform.
				"annotations": annotationsFor(req),
			}},
		}, nil

	case domain.PurposeDriftProposal:
		return map[string]any{
			"summary":   "Proposed update to " + subject + " to reflect the observed implementation.",
			"rationale": "Addresses the cited drift findings.",
			// A proposal that cites no finding is rejected by the validator, so
			// the simulator always carries the citations through.
			"addresses_findings": findingIDs(req),
			"changes": []map[string]any{
				{"path": "/then", "operation": "add", "value": "the response includes a correlation identifier"},
			},
		}, nil

	case domain.PurposeReverseNarrate:
		return map[string]any{
			"narrative": "The component exposes the operations discovered by static analysis.",
			// Every claim is tagged with the fact it rests on. The grounding
			// guardrail drops any claim without one, which is what keeps a
			// narration from inventing behaviour.
			"claims": claimsFrom(source),
		}, nil

	case domain.PurposeExplain:
		return map[string]any{
			"explanation": "This is a non-authoritative explanation generated for readability.",
			"advisory":    true,
		}, nil

	default:
		return nil, fmt.Errorf("simulator: no generation rule for purpose %s", req.Purpose)
	}
}

// ---------------------------------------------------------------------------
// Deterministic helpers
// ---------------------------------------------------------------------------

func seedOf(req domain.CompletionRequest, rendered domain.RenderedPrompt) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(req.Purpose))
	_, _ = h.Write([]byte(req.Prompt.String()))
	_, _ = h.Write([]byte(rendered.Instruction))
	for _, c := range rendered.Channels {
		_, _ = h.Write([]byte(c.Label))
		_, _ = h.Write([]byte(c.Content))
	}
	keys := make([]string, 0, len(req.Variables))
	for k := range req.Variables {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte(fmt.Sprint(req.Variables[k])))
	}
	return h.Sum64()
}

func channelText(channels []domain.DataChannel) string {
	var sb strings.Builder
	for _, c := range channels {
		sb.WriteString(c.Content)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func subjectOf(req domain.CompletionRequest, rendered domain.RenderedPrompt, source string) string {
	if v, ok := req.Variables["subject"].(string); ok && v != "" {
		return v
	}
	if v, ok := req.Variables["title"].(string); ok && v != "" {
		return v
	}
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && len(line) < 120 {
			return line
		}
	}
	if rendered.Instruction != "" {
		return firstSentence(rendered.Instruction)
	}
	return "Untitled capability"
}

func firstSentence(s string) string {
	if i := strings.IndexAny(s, ".!?\n"); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	if len(s) > 100 {
		return strings.TrimSpace(s[:100])
	}
	return strings.TrimSpace(s)
}

// discoveryQuestions covers the twelve dimensions the brief requires.
func discoveryQuestions(subject string) []map[string]any {
	dims := []struct{ dimension, question string }{
		{"actors", "Who performs " + subject + ", and who is affected by it?"},
		{"business_goals", "What outcome does " + subject + " achieve for the business?"},
		{"functional_requirements", "What must the system do, step by step?"},
		{"non_functional_requirements", "What latency, throughput and availability are required?"},
		{"business_rules", "What rules constrain when this may and may not happen?"},
		{"integrations", "Which external systems participate?"},
		{"security", "What must be authenticated, authorized or encrypted?"},
		{"compliance", "Which regulations or internal policies apply?"},
		{"availability", "What downtime is acceptable, and over what window?"},
		{"scalability", "What volume must this handle at peak, and in a year?"},
		{"observability", "How will you know it is working, and how will you debug it?"},
		{"disaster_recovery", "What recovery time and recovery point are required?"},
	}
	out := make([]map[string]any, 0, len(dims))
	for i, d := range dims {
		out = append(out, map[string]any{
			"id": fmt.Sprintf("Q-%02d", i+1), "dimension": d.dimension, "question": d.question,
		})
	}
	return out
}

func extractActors(source string) []string {
	seen := map[string]bool{}
	var out []string
	for _, candidate := range []string{"user", "administrator", "operator", "auditor",
		"customer", "reviewer", "approver", "service"} {
		if strings.Contains(strings.ToLower(source), candidate) && !seen[candidate] {
			seen[candidate] = true
			out = append(out, strings.ToUpper(candidate[:1])+candidate[1:])
		}
	}
	if len(out) == 0 {
		out = []string{"User", "Administrator"}
	}
	return out
}

func extractGoals(source string) []string {
	var out []string
	for _, line := range strings.Split(source, "\n") {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		if strings.HasPrefix(low, "goal") || strings.Contains(low, "so that") {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		out = []string{"Deliver the described capability with governed traceability."}
	}
	return out
}

func extractRequirements(source, prefix string) []map[string]any {
	var out []map[string]any
	n := 1
	for _, line := range strings.Split(source, "\n") {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		if l == "" {
			continue
		}
		if strings.Contains(low, "must") || strings.Contains(low, "shall") ||
			strings.Contains(low, "should") {
			out = append(out, map[string]any{
				"id": fmt.Sprintf("%s-%03d", prefix, n), "statement": l,
			})
			n++
		}
	}
	if len(out) == 0 {
		out = []map[string]any{{
			"id": prefix + "-001",
			"statement": "The system must implement the capability described in the discovery " +
				"conversation.",
		}}
	}
	return out
}

func extractRules(source string) []string {
	var out []string
	for _, line := range strings.Split(source, "\n") {
		l := strings.TrimSpace(line)
		low := strings.ToLower(l)
		if strings.HasPrefix(low, "if ") || strings.Contains(low, " only if ") ||
			strings.Contains(low, "must not") {
			out = append(out, l)
		}
	}
	return out
}

func defaultNFRs() []map[string]any {
	return []map[string]any{
		{"id": "NFR-001", "category": "performance", "statement": "p95 latency under 500 ms."},
		{"id": "NFR-002", "category": "availability", "statement": "99.9% monthly availability."},
		{"id": "NFR-003", "category": "observability",
			"statement": "Every request carries trace, tenant and request identifiers."},
		{"id": "NFR-004", "category": "disaster_recovery",
			"statement": "Recovery time under four hours, recovery point under fifteen minutes."},
	}
}

func defaultSecurityRequirements() []string {
	return []string{
		"All access is authenticated and authorized at tenant and project scope.",
		"Privileged actions require a recent multi-factor authentication.",
		"Every governed operation is recorded in a tamper-evident audit trail.",
	}
}

// openQuestions is where the simulator declines to guess.
//
// Surfacing an ambiguity is more useful than inventing a resolution, and it
// keeps the human in the loop where the input genuinely does not say.
func openQuestions(source string) []string {
	var out []string
	if !strings.Contains(strings.ToLower(source), "retention") {
		out = append(out, "How long must the records be retained?")
	}
	if !strings.Contains(strings.ToLower(source), "volume") &&
		!strings.Contains(strings.ToLower(source), "throughput") {
		out = append(out, "What is the expected peak volume?")
	}
	if len(out) == 0 {
		out = []string{"Confirm the acceptance criteria with the approving stakeholder."}
	}
	return out
}

func annotationsFor(req domain.CompletionRequest) []string {
	out := make([]string, 0, len(req.InputArtifacts))
	for _, a := range req.InputArtifacts {
		out = append(out, "@spec "+a.ArtifactID.String())
	}
	if len(out) == 0 {
		out = []string{"@spec SPEC-000"}
	}
	return out
}

func findingIDs(req domain.CompletionRequest) []string {
	if v, ok := req.Variables["finding_ids"].([]string); ok {
		return v
	}
	if v, ok := req.Variables["finding_ids"].([]any); ok {
		out := make([]string, 0, len(v))
		for _, e := range v {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

// claimsFrom emits one claim per fact line, each carrying its source reference.
func claimsFrom(source string) []map[string]any {
	var out []map[string]any
	for i, line := range strings.Split(source, "\n") {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}
		out = append(out, map[string]any{
			"claim":     l,
			"reference": fmt.Sprintf("fact:%d", i),
		})
		if len(out) >= 25 {
			break
		}
	}
	return out
}

// groundingFor reports which claims rest on supplied facts. A claim with no
// reference is reported ungrounded, and the grounding guardrail drops it.
func groundingFor(req domain.CompletionRequest, content map[string]any) []domain.GroundingClaim {
	claims, ok := content["claims"].([]map[string]any)
	if !ok {
		return nil
	}
	out := make([]domain.GroundingClaim, 0, len(claims))
	for _, c := range claims {
		ref, _ := c["reference"].(string)
		out = append(out, domain.GroundingClaim{
			Claim:     fmt.Sprint(c["claim"]),
			Grounded:  ref != "",
			Reference: ref,
		})
	}
	return out
}

func estimateTokens(rendered domain.RenderedPrompt) int {
	n := len(rendered.System) + len(rendered.Instruction)
	for _, c := range rendered.Channels {
		n += len(c.Content)
	}
	return n / 4
}

// deterministicPick chooses from a list using the seed, so variation across
// different inputs is possible while any single input stays reproducible.
func deterministicPick(seed uint64, options []string) string {
	if len(options) == 0 {
		return ""
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], seed)
	h := fnv.New32a()
	_, _ = h.Write(buf[:])
	return options[int(h.Sum32())%len(options)]
}
