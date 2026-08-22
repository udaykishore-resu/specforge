// Package types holds the value objects shared across every bounded context.
//
// Everything here is immutable, validated at construction, and free of I/O.
// Domain packages may import this and nothing else outside the standard library.
package types

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

// TenantID is the isolation key. Every row, object, cache key, event and secret
// in the platform belongs to exactly one tenant.
type TenantID string

// ProjectID identifies a delivery unit within a tenant.
type ProjectID string

// PrincipalID identifies a human user, service account or system actor.
type PrincipalID string

// ArtifactID is the human-meaningful, project-scoped identity of a governed
// artifact, for example "SPEC-AUTH-001". It is never reused, even after the
// artifact is abandoned.
type ArtifactID string

// LinkID identifies a trace link.
type LinkID string

func (t TenantID) String() string    { return string(t) }
func (p ProjectID) String() string   { return string(p) }
func (p PrincipalID) String() string { return string(p) }
func (a ArtifactID) String() string  { return string(a) }
func (l LinkID) String() string      { return string(l) }

func (t TenantID) Empty() bool  { return t == "" }
func (p ProjectID) Empty() bool { return p == "" }

var (
	uuidRE       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	slugRE       = regexp.MustCompile(`^[a-z][a-z0-9-]{2,39}$`)
	projectKeyRE = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}$`)
	artifactIDRE = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Za-z0-9]+)+$`)
)

// ParseTenantID validates and returns a TenantID.
func ParseTenantID(s string) (TenantID, error) {
	if !uuidRE.MatchString(s) {
		return "", fmt.Errorf("invalid tenant id %q: must be a lowercase UUID", s)
	}
	return TenantID(s), nil
}

// ParseProjectID validates and returns a ProjectID.
func ParseProjectID(s string) (ProjectID, error) {
	if !uuidRE.MatchString(s) {
		return "", fmt.Errorf("invalid project id %q: must be a lowercase UUID", s)
	}
	return ProjectID(s), nil
}

// ParsePrincipalID validates and returns a PrincipalID.
func ParsePrincipalID(s string) (PrincipalID, error) {
	if !uuidRE.MatchString(s) {
		return "", fmt.Errorf("invalid principal id %q: must be a lowercase UUID", s)
	}
	return PrincipalID(s), nil
}

// ValidateSlug checks a tenant slug.
func ValidateSlug(s string) error {
	if !slugRE.MatchString(s) {
		return fmt.Errorf("invalid slug %q: 3-40 chars, lowercase letters, digits and hyphens, "+
			"must start with a letter", s)
	}
	return nil
}

// ValidateProjectKey checks a project key, which becomes the artifact ID namespace.
func ValidateProjectKey(s string) error {
	if !projectKeyRE.MatchString(s) {
		return fmt.Errorf("invalid project key %q: 2-10 uppercase letters and digits, "+
			"must start with a letter", s)
	}
	return nil
}

// ParseArtifactID validates the artifact identifier shape.
func ParseArtifactID(s string) (ArtifactID, error) {
	if len(s) > 120 {
		return "", fmt.Errorf("artifact id %q exceeds 120 characters", s)
	}
	if !artifactIDRE.MatchString(s) {
		return "", fmt.Errorf("invalid artifact id %q: expected a form like SPEC-AUTH-001", s)
	}
	return ArtifactID(s), nil
}

// ---------------------------------------------------------------------------
// Artifact taxonomy
// ---------------------------------------------------------------------------

// ArtifactType enumerates the governed artifact kinds.
type ArtifactType string

const (
	ArtifactRequirement   ArtifactType = "REQUIREMENT"
	ArtifactPRD           ArtifactType = "PRD"
	ArtifactSpecification ArtifactType = "SPECIFICATION"
	ArtifactBPMNProcess   ArtifactType = "BPMN_PROCESS"
	ArtifactArchitecture  ArtifactType = "ARCHITECTURE"
	ArtifactAPIContract   ArtifactType = "API_CONTRACT"
	ArtifactDataModel     ArtifactType = "DATA_MODEL"
	ArtifactSequence      ArtifactType = "SEQUENCE"
	ArtifactStateMachine  ArtifactType = "STATE_MACHINE"
	ArtifactCodeUnit      ArtifactType = "CODE_UNIT"
	ArtifactTestCase      ArtifactType = "TEST_CASE"
	ArtifactPipelineDef   ArtifactType = "PIPELINE_DEF"
	ArtifactDeployment    ArtifactType = "DEPLOYMENT"
	ArtifactPolicy        ArtifactType = "POLICY"
	ArtifactEvidence      ArtifactType = "EVIDENCE"
	ArtifactPrompt        ArtifactType = "PROMPT"
)

var artifactTypes = map[ArtifactType]struct {
	prefix        string
	contentSchema string
	// requiresFourEyes marks types whose approval defaults to two-person control.
	requiresFourEyes bool
}{
	ArtifactRequirement:   {"REQ", "specforge.requirement.v1", false},
	ArtifactPRD:           {"PRD", "specforge.prd.v1", true},
	ArtifactSpecification: {"SPEC", "specforge.spec.v1", false},
	ArtifactBPMNProcess:   {"BPMN", "specforge.bpmn.v1", false},
	ArtifactArchitecture:  {"ARCH", "specforge.architecture.v1", true},
	ArtifactAPIContract:   {"API", "specforge.api.v1", false},
	ArtifactDataModel:     {"DATA", "specforge.datamodel.v1", false},
	ArtifactSequence:      {"SEQ", "specforge.sequence.v1", false},
	ArtifactStateMachine:  {"FSM", "specforge.statemachine.v1", false},
	ArtifactCodeUnit:      {"CODE", "specforge.codeunit.v1", false},
	ArtifactTestCase:      {"TEST", "specforge.testcase.v1", false},
	ArtifactPipelineDef:   {"PIPE", "specforge.pipeline.v1", false},
	ArtifactDeployment:    {"DEP", "specforge.deployment.v1", false},
	ArtifactPolicy:        {"POL", "specforge.policy.v1", true},
	ArtifactEvidence:      {"EVD", "specforge.evidence.v1", false},
	ArtifactPrompt:        {"PRM", "specforge.prompt.v1", false},
}

// Valid reports whether t is a known artifact type.
func (t ArtifactType) Valid() bool { _, ok := artifactTypes[t]; return ok }

// Prefix returns the conventional artifact ID prefix for the type.
func (t ArtifactType) Prefix() string { return artifactTypes[t].prefix }

// DefaultContentSchema returns the payload schema identifier for the type.
func (t ArtifactType) DefaultContentSchema() string { return artifactTypes[t].contentSchema }

// RequiresFourEyes reports whether approval of this type defaults to two-person
// control. Tenant policy may widen this but never narrow it below the default.
func (t ArtifactType) RequiresFourEyes() bool { return artifactTypes[t].requiresFourEyes }

// ParseArtifactType validates an artifact type string.
func ParseArtifactType(s string) (ArtifactType, error) {
	t := ArtifactType(strings.ToUpper(strings.TrimSpace(s)))
	if !t.Valid() {
		return "", fmt.Errorf("unknown artifact type %q", s)
	}
	return t, nil
}

// AllArtifactTypes returns every known artifact type, for validation and docs.
func AllArtifactTypes() []ArtifactType {
	out := make([]ArtifactType, 0, len(artifactTypes))
	for t := range artifactTypes {
		out = append(out, t)
	}
	return out
}

// ---------------------------------------------------------------------------
// Trace links
// ---------------------------------------------------------------------------

// LinkType is the semantic of a directed edge in the artifact graph.
type LinkType string

const (
	LinkDerivedFrom   LinkType = "DERIVED_FROM"
	LinkSatisfies     LinkType = "SATISFIES"
	LinkImplements    LinkType = "IMPLEMENTS"
	LinkRepresentedBy LinkType = "REPRESENTED_BY"
	LinkVerifies      LinkType = "VERIFIES"
	LinkRealizedBy    LinkType = "REALIZED_BY"
	LinkDeploys       LinkType = "DEPLOYS"
	LinkContains      LinkType = "CONTAINS"
	LinkDependsOn     LinkType = "DEPENDS_ON"
	LinkSupersedes    LinkType = "SUPERSEDES"
	LinkGoverns       LinkType = "GOVERNS"
	LinkEvidences     LinkType = "EVIDENCES"
	LinkConflictsWith LinkType = "CONFLICTS_WITH"
)

// linkInverse maps each link type to the name of its reverse traversal.
var linkInverse = map[LinkType]string{
	LinkDerivedFrom:   "DERIVES",
	LinkSatisfies:     "SATISFIED_BY",
	LinkImplements:    "IMPLEMENTED_BY",
	LinkRepresentedBy: "REPRESENTS",
	LinkVerifies:      "VERIFIED_BY",
	LinkRealizedBy:    "REALIZES",
	LinkDeploys:       "DEPLOYED_BY",
	LinkContains:      "CONTAINED_BY",
	LinkDependsOn:     "DEPENDED_ON_BY",
	LinkSupersedes:    "SUPERSEDED_BY",
	LinkGoverns:       "GOVERNED_BY",
	LinkEvidences:     "EVIDENCED_BY",
	LinkConflictsWith: "CONFLICTS_WITH", // symmetric
}

// AllLinkTypes returns every known link type, for validation and docs.
func AllLinkTypes() []LinkType {
	out := make([]LinkType, 0, len(linkInverse))
	for t := range linkInverse {
		out = append(out, t)
	}
	return out
}

func (l LinkType) Valid() bool     { _, ok := linkInverse[l]; return ok }
func (l LinkType) Inverse() string { return linkInverse[l] }

// Symmetric reports whether the relation reads the same in both directions.
func (l LinkType) Symmetric() bool { return l == LinkConflictsWith }

// ParseLinkType validates a link type string.
func ParseLinkType(s string) (LinkType, error) {
	t := LinkType(strings.ToUpper(strings.TrimSpace(s)))
	if !t.Valid() {
		return "", fmt.Errorf("unknown link type %q", s)
	}
	return t, nil
}

// LinkOrigin records who or what asserted a link. It determines whether the
// link may be accepted without a governance disposition.
type LinkOrigin string

const (
	OriginHuman       LinkOrigin = "HUMAN"
	OriginAnalyzer    LinkOrigin = "ANALYZER"
	OriginLLMProposed LinkOrigin = "LLM_PROPOSED"
)

func (o LinkOrigin) Valid() bool {
	switch o {
	case OriginHuman, OriginAnalyzer, OriginLLMProposed:
		return true
	}
	return false
}

// RequiresDisposition reports whether accepting a link of this origin needs a
// recorded governance decision. This is the "AI proposes, governance approves"
// rule in its most compact form.
func (o LinkOrigin) RequiresDisposition() bool { return o == OriginLLMProposed }

// LinkStatus is the lifecycle state of a trace link.
type LinkStatus string

const (
	LinkProposed LinkStatus = "PROPOSED"
	LinkAccepted LinkStatus = "ACCEPTED"
	LinkRejected LinkStatus = "REJECTED"
	LinkStale    LinkStatus = "STALE"
)

// AllLinkStatuses returns every link lifecycle state, for validation and docs.
func AllLinkStatuses() []LinkStatus {
	return []LinkStatus{LinkProposed, LinkAccepted, LinkRejected, LinkStale}
}

func (s LinkStatus) Valid() bool {
	switch s {
	case LinkProposed, LinkAccepted, LinkRejected, LinkStale:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

// GeneratorKind records what produced an artifact version. Every version has one;
// there is no anonymous content in the graph.
type GeneratorKind string

const (
	GeneratedByUser      GeneratorKind = "USER"
	GeneratedByAnalyzer  GeneratorKind = "ANALYZER"
	GeneratedByInference GeneratorKind = "INFERENCE"
	GeneratedByImport    GeneratorKind = "IMPORT"
)

func (k GeneratorKind) Valid() bool {
	switch k {
	case GeneratedByUser, GeneratedByAnalyzer, GeneratedByInference, GeneratedByImport:
		return true
	}
	return false
}

// IsAI reports whether the content originated from a model and therefore
// requires the AI provenance fields and human review by default.
func (k GeneratorKind) IsAI() bool { return k == GeneratedByInference }

// ---------------------------------------------------------------------------
// Isolation and deployment
// ---------------------------------------------------------------------------

// IsolationMode selects how strongly a tenant's storage is separated.
// Row-level security applies in all modes; the mode changes what else is
// separated on top of it.
type IsolationMode string

const (
	IsolationShared          IsolationMode = "shared"
	IsolationDedicatedSchema IsolationMode = "dedicated_schema"
	IsolationSingleTenant    IsolationMode = "single_tenant"
)

func (m IsolationMode) Valid() bool {
	switch m {
	case IsolationShared, IsolationDedicatedSchema, IsolationSingleTenant:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Risk and severity
// ---------------------------------------------------------------------------

// Severity grades findings and audit records.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// Weight returns the numeric weight used by the consistency score.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 8
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Content addressing
// ---------------------------------------------------------------------------

// ContentHash is a "sha256:<64 hex>" digest over an artifact's canonical form.
type ContentHash string

var contentHashRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func (h ContentHash) Valid() bool     { return contentHashRE.MatchString(string(h)) }
func (h ContentHash) String() string  { return string(h) }
func (h ContentHash) HexOnly() string { return strings.TrimPrefix(string(h), "sha256:") }

// Short renders an abbreviated hash for logs and UI labels.
func (h ContentHash) Short() string {
	s := string(h)
	if len(s) > 19 {
		return s[:19]
	}
	return s
}

// ParseContentHash validates a content hash.
func ParseContentHash(s string) (ContentHash, error) {
	h := ContentHash(s)
	if !h.Valid() {
		return "", fmt.Errorf("invalid content hash %q: expected sha256:<64 hex chars>", s)
	}
	return h, nil
}

// EvidenceRef points at an immutable object in the evidence store.
type EvidenceRef struct {
	EvidenceID string      `json:"evidence_id"`
	Digest     ContentHash `json:"digest"`
	MediaType  string      `json:"media_type"`
	StorageRef string      `json:"storage_ref"`
	Bytes      int64       `json:"bytes,omitempty"`
}

// Valid reports whether the reference is complete enough to be resolvable.
func (e EvidenceRef) Valid() bool {
	return e.EvidenceID != "" && e.Digest.Valid() && e.StorageRef != ""
}

// ArtifactRef names a specific artifact version.
type ArtifactRef struct {
	ArtifactID ArtifactID `json:"artifact_id"`
	Version    int        `json:"version"`
}

func (r ArtifactRef) String() string { return fmt.Sprintf("%s@v%d", r.ArtifactID, r.Version) }
func (r ArtifactRef) Zero() bool     { return r.ArtifactID == "" }

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

// Now returns the current time in UTC, truncated to microseconds.
//
// PostgreSQL's timestamptz resolution is one microsecond. Content hashes and
// audit chain hashes cover timestamps, so a value that cannot round-trip
// through the database would make every stored artifact fail its own integrity
// check on read. Truncating at construction keeps the canonical form and the
// persisted form identical.
func Now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// NormalizeTime truncates a timestamp to the precision the database preserves.
func NormalizeTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }
