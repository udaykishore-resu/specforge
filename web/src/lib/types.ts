/**
 * The API's shapes, mirroring api/openapi/specforge.v1.yaml.
 *
 * These are hand-written rather than generated because the console consumes a
 * deliberate subset. The Go contract test (test/contract) is what keeps the
 * document honest against the server; this file is kept in step with the
 * document.
 */

export type ArtifactType =
  | 'PRD'
  | 'REQUIREMENT'
  | 'SPECIFICATION'
  | 'BPMN_PROCESS'
  | 'ARCHITECTURE'
  | 'API_CONTRACT'
  | 'DATA_MODEL'
  | 'SEQUENCE'
  | 'STATE_MACHINE'
  | 'CODE_UNIT'
  | 'TEST_CASE'
  | 'PIPELINE_DEF'
  | 'DEPLOYMENT'
  | 'POLICY'
  | 'EVIDENCE'
  | 'PROMPT'

export type ArtifactStatus =
  | 'DRAFT'
  | 'AI_REVIEW'
  | 'USER_REVIEW'
  | 'CHANGES_REQUESTED'
  | 'APPROVED'
  | 'FROZEN'
  | 'SUPERSEDED'
  | 'ABANDONED'

export type LinkStatus = 'PROPOSED' | 'ACCEPTED' | 'REJECTED' | 'STALE'
export type LinkOrigin = 'HUMAN' | 'ANALYZER' | 'LLM_PROPOSED'
export type Severity = 'INFO' | 'NOTICE' | 'WARNING' | 'CRITICAL'
export type Outcome = 'SUCCESS' | 'FAILURE' | 'DENIED'

export interface Tenant {
  tenant_id: string
  slug: string
  name: string
  status: string
  isolation_mode: string
  region: string
  settings?: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface Project {
  project_id: string
  tenant_id: string
  key: string
  name: string
  description: string
  status: string
  pdlc_phase: string
  graph_version: number
  created_at: string
  updated_at: string
}

export interface Principal {
  principal_id?: string
  tenant_id?: string
  kind?: string
  display?: string
  status?: string
  roles?: { role: string; project_id?: string }[]
  permissions?: string[]
  auth_time?: string
  amr?: string[]
}

export interface ArtifactRef {
  artifact_id: string
  version: number
}

export interface Generator {
  kind: string
  prompt_version?: string
  model?: string
  provider?: string
  guardrail_chain_version?: string
  inference_id?: string
  analyzer?: string
  analyzer_version?: string
}

export interface Artifact {
  artifact_id: string
  artifact_type: ArtifactType
  title: string
  current_version: number
  status: ArtifactStatus
  labels?: Record<string, string>
  created_by: string
  created_at: string
  updated_at: string
}

export interface GateDecision {
  gate: string
  decision: 'ALLOW' | 'WARN' | 'BLOCK'
  detail?: string
  policy_version?: string
}

export interface ApprovalEvidenceRef {
  evidence_id: string
  digest: string
  media_type?: string
  storage_ref?: string
  gate_decisions?: GateDecision[]
  approver_auth_time?: string
}

export interface ArtifactVersion {
  artifact_id: string
  artifact_type: ArtifactType
  version: number
  status: ArtifactStatus
  content_schema?: string
  content: Record<string, unknown>
  content_hash: string
  content_ref?: string
  change_summary?: string
  generator?: Generator
  previous_version?: number
  parent_artifact?: ArtifactRef
  source_artifact?: ArtifactRef
  approved_by?: string
  approved_at?: string
  approval_comment?: string
  approval_evidence?: ApprovalEvidenceRef
  sealed: boolean
  sealed_at?: string
  created_by: string
  created_at: string
  updated_at: string
  version_no: number
}

export interface TraceLink {
  link_id: string
  from: ArtifactRef
  to: ArtifactRef
  link_type: string
  origin: LinkOrigin
  confidence: number
  status: LinkStatus
  rationale?: string
  disposition_id?: string
  created_by: string
  created_at: string
}

/** One edge in a traversal. */
export interface Hop {
  from: ArtifactRef
  to: ArtifactRef
  link_type: string
  origin: LinkOrigin
  confidence: number
  status: LinkStatus
}

/** A route from the traversal's origin to one reachable artifact. */
export interface TracePath {
  target: ArtifactRef
  artifact_type: ArtifactType
  title?: string
  status?: string
  hops: Hop[]
  depth: number
}

export interface Paths {
  start: ArtifactRef
  direction: string
  paths: TracePath[]
  /** True when the depth bound stopped the walk, so the answer is partial. */
  truncated: boolean
}

export type ImpactSeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface Impacted {
  target: ArtifactRef
  artifact_type: ArtifactType
  status: string
  distance: number
  severity: ImpactSeverity
  reason: string
  path: Hop[]
}

export interface ImpactSet {
  subject: ArtifactRef
  impacted: Impacted[]
  truncated: boolean
  /** Impacted artifacts at HIGH or above — the number a reviewer wants first. */
  blast_radius: number
}

export interface AuditRecord {
  sequence: number
  id: string
  project_id?: string
  action: string
  outcome: Outcome
  severity: Severity
  actor?: Record<string, unknown>
  target?: Record<string, unknown>
  attributes?: Record<string, unknown>
  request_id?: string
  trace_id?: string
  occurred_at: string
  prev_hash: string
  record_hash: string
}

export interface VerifyReport {
  tenant_id: string
  from: number
  to: number
  records_checked: number
  valid: boolean
  failed_at?: number
  reason?: string
  gap_at?: number
  anchored_at?: number
}

/** Statuses whose bytes can no longer change. */
export const SEALED_STATUSES: ArtifactStatus[] = ['APPROVED', 'FROZEN', 'SUPERSEDED', 'ABANDONED']

export function isSealed(status: ArtifactStatus): boolean {
  return SEALED_STATUSES.includes(status)
}
