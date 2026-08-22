import 'server-only'

import { readSession } from './session'
import type {
  Artifact,
  ArtifactVersion,
  AuditRecord,
  Paths,
  Principal,
  Project,
  Tenant,
  TraceLink,
  VerifyReport,
} from './types'

/**
 * The server-side client for the platform API.
 *
 * Everything here runs on the Next.js server. The access token is attached
 * here and never sent to the browser, which is the whole reason this console is
 * a server-rendered application rather than a single-page app talking to the
 * API directly.
 */

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly detail: string
  readonly traceId?: string

  constructor(status: number, code: string, detail: string, traceId?: string) {
    super(detail || code)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.detail = detail
    this.traceId = traceId
  }

  /** True when re-authentication with a second factor would fix this. */
  get needsStepUp(): boolean {
    return this.code === 'authz.step_up_required'
  }

  /** True when the caller is refused because they authored the artifact. */
  get isFourEyes(): boolean {
    return this.code === 'authz.four_eyes_violated'
  }
}

interface Problem {
  type?: string
  title?: string
  status?: number
  detail?: string
  code?: string
  trace_id?: string
}

function baseUrl(): string {
  const url = process.env.SPECFORGE_API_URL
  if (!url) throw new Error('SPECFORGE_API_URL is not set')
  return url.replace(/\/$/, '')
}

interface RequestOptions {
  method?: string
  body?: unknown
  /** Sent as Idempotency-Key so a retried write cannot double-apply. */
  idempotencyKey?: string
  /** Optimistic concurrency token from a previous read. */
  ifMatch?: string
  /** Next.js cache directive. Governed reads default to no-store. */
  revalidate?: number
}

async function call<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const session = await readSession()
  if (!session) {
    throw new ApiError(401, 'session.missing', 'Your session has expired. Sign in again.')
  }

  const headers: Record<string, string> = {
    Accept: 'application/json',
    Authorization: `Bearer ${session.accessToken}`,
  }
  if (options.body !== undefined) headers['Content-Type'] = 'application/json'
  if (options.idempotencyKey) headers['Idempotency-Key'] = options.idempotencyKey
  if (options.ifMatch) headers['If-Match'] = options.ifMatch

  const res = await fetch(`${baseUrl()}${path}`, {
    method: options.method ?? 'GET',
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    // Governed data is never served from a cache by default. Showing a stale
    // approval state would be worse than showing a spinner.
    cache: options.revalidate === undefined ? 'no-store' : undefined,
    next: options.revalidate === undefined ? undefined : { revalidate: options.revalidate },
  })

  if (res.status === 204) return undefined as T

  const text = await res.text()
  if (!res.ok) {
    let problem: Problem = {}
    try {
      problem = JSON.parse(text) as Problem
    } catch {
      // Not a problem+json document — a proxy error page, most likely.
    }
    throw new ApiError(
      res.status,
      problem.code ?? `http.${res.status}`,
      problem.detail ?? problem.title ?? text.slice(0, 300) ?? 'The request failed.',
      problem.trace_id,
    )
  }

  return (text ? JSON.parse(text) : undefined) as T
}

interface Items<T> {
  items: T[]
  next_cursor?: string
}

export const api = {
  me: () => call<Principal>('/api/v1/auth/me'),

  tenants: () => call<Items<Tenant>>('/api/v1/tenants'),
  tenant: (tenantId: string) => call<Tenant>(`/api/v1/tenants/${tenantId}`),

  projects: (tenantId: string) => call<Items<Project>>(`/api/v1/tenants/${tenantId}/projects`),
  project: (tenantId: string, projectId: string) =>
    call<Project>(`/api/v1/tenants/${tenantId}/projects/${projectId}`),
  createProject: (tenantId: string, body: { key: string; name: string; description: string }, idempotencyKey: string) =>
    call<Project>(`/api/v1/tenants/${tenantId}/projects`, { method: 'POST', body, idempotencyKey }),

  principals: (tenantId: string) => call<Items<Principal>>(`/api/v1/tenants/${tenantId}/principals`),

  artifacts: (tenantId: string, projectId: string, query?: { type?: string; status?: string }) => {
    const search = new URLSearchParams()
    if (query?.type) search.set('type', query.type)
    if (query?.status) search.set('status', query.status)
    const suffix = search.toString() ? `?${search}` : ''
    return call<Items<Artifact>>(`/api/v1/tenants/${tenantId}/projects/${projectId}/artifacts${suffix}`)
  },

  artifact: (tenantId: string, projectId: string, artifactId: string) =>
    call<{ artifact: Artifact; versions: ArtifactVersion[] }>(
      `/api/v1/tenants/${tenantId}/projects/${projectId}/artifacts/${artifactId}`,
    ),

  version: (tenantId: string, projectId: string, artifactId: string, version: number) =>
    call<ArtifactVersion>(
      `/api/v1/tenants/${tenantId}/projects/${projectId}/artifacts/${artifactId}/versions/${version}`,
    ),

  submit: (tenantId: string, projectId: string, artifactId: string, version: number, comment: string) =>
    call<ArtifactVersion>(
      `/api/v1/tenants/${tenantId}/projects/${projectId}/artifacts/${artifactId}/versions/${version}/submit`,
      { method: 'POST', body: { comment } },
    ),

  requestChanges: (
    tenantId: string,
    projectId: string,
    artifactId: string,
    version: number,
    comment: string,
  ) =>
    call<ArtifactVersion>(
      `/api/v1/tenants/${tenantId}/projects/${projectId}/artifacts/${artifactId}/versions/${version}/request-changes`,
      { method: 'POST', body: { comment } },
    ),

  approve: (
    tenantId: string,
    projectId: string,
    artifactId: string,
    version: number,
    comment: string,
    idempotencyKey: string,
  ) =>
    call<ArtifactVersion>(
      `/api/v1/tenants/${tenantId}/projects/${projectId}/artifacts/${artifactId}/versions/${version}/approve`,
      { method: 'POST', body: { comment }, idempotencyKey },
    ),

  revise: (
    tenantId: string,
    projectId: string,
    artifactId: string,
    changeSummary: string,
    idempotencyKey: string,
  ) =>
    call<ArtifactVersion>(
      `/api/v1/tenants/${tenantId}/projects/${projectId}/artifacts/${artifactId}/revise`,
      { method: 'POST', body: { change_summary: changeSummary }, idempotencyKey },
    ),

  links: (tenantId: string, projectId: string, query?: { from?: string; to?: string }) => {
    const search = new URLSearchParams()
    if (query?.from) search.set('from', query.from)
    if (query?.to) search.set('to', query.to)
    const suffix = search.toString() ? `?${search}` : ''
    return call<Items<TraceLink>>(`/api/v1/tenants/${tenantId}/projects/${projectId}/links${suffix}`)
  },

  acceptLink: (tenantId: string, projectId: string, linkId: string, comment: string) =>
    call<TraceLink>(`/api/v1/tenants/${tenantId}/projects/${projectId}/links/${linkId}/accept`, {
      method: 'POST',
      body: { comment },
    }),

  rejectLink: (tenantId: string, projectId: string, linkId: string, comment: string) =>
    call<TraceLink>(`/api/v1/tenants/${tenantId}/projects/${projectId}/links/${linkId}/reject`, {
      method: 'POST',
      body: { comment },
    }),

  upstream: (tenantId: string, projectId: string, artifact: string, version = 1) =>
    call<Paths>(
      `/api/v1/tenants/${tenantId}/projects/${projectId}/trace/upstream?artifact=${encodeURIComponent(artifact)}&version=${version}`,
    ),

  downstream: (tenantId: string, projectId: string, artifact: string, version = 1) =>
    call<Paths>(
      `/api/v1/tenants/${tenantId}/projects/${projectId}/trace/downstream?artifact=${encodeURIComponent(artifact)}&version=${version}`,
    ),

  audit: (tenantId: string, query?: { action?: string; severity?: string; limit?: number }) => {
    const search = new URLSearchParams()
    if (query?.action) search.set('action', query.action)
    if (query?.severity) search.set('severity', query.severity)
    search.set('limit', String(query?.limit ?? 50))
    return call<Items<AuditRecord>>(`/api/v1/tenants/${tenantId}/audit?${search}`)
  },

  verifyAudit: (tenantId: string) =>
    call<VerifyReport>(`/api/v1/tenants/${tenantId}/audit/verify`, { method: 'POST', body: { from: 1, to: 0 } }),
}

/**
 * Runs a read and returns an error object instead of throwing.
 *
 * Page components use this so that one failing panel degrades to an inline
 * message rather than replacing the entire page with an error boundary. A
 * console that goes blank because the audit widget timed out is a console
 * people stop trusting during an incident.
 */
export async function attempt<T>(fn: () => Promise<T>): Promise<{ data: T } | { error: ApiError }> {
  try {
    return { data: await fn() }
  } catch (err) {
    if (err instanceof ApiError) return { error: err }
    return { error: new ApiError(500, 'client.unexpected', err instanceof Error ? err.message : 'Unknown error') }
  }
}
