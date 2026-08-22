import Link from 'next/link'

import { Shell } from '@/components/shell'
import {
  Card,
  Cell,
  EmptyState,
  ErrorNote,
  LinkStatusBadge,
  Row,
  Stat,
  StatusBadge,
  Table,
  Time,
} from '@/components/ui'
import { api, attempt } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import type { ArtifactStatus } from '@/lib/types'

export const dynamic = 'force-dynamic'

export default async function ProjectPage({ params }: { params: Promise<{ projectId: string }> }) {
  const { projectId } = await params
  const session = await requireSession(`/projects/${projectId}`)
  const tenantId = session.tenantId

  const [tenantRes, projectsRes, projectRes, artifactsRes, linksRes] = await Promise.all([
    attempt(() => api.tenant(tenantId)),
    attempt(() => api.projects(tenantId)),
    attempt(() => api.project(tenantId, projectId)),
    attempt(() => api.artifacts(tenantId, projectId)),
    attempt(() => api.links(tenantId, projectId)),
  ])

  const tenant = 'data' in tenantRes ? tenantRes.data : undefined
  const projects = 'data' in projectsRes ? projectsRes.data.items : []
  const artifacts = 'data' in artifactsRes ? artifactsRes.data.items : []
  const links = 'data' in linksRes ? linksRes.data.items : []

  if ('error' in projectRes) {
    return (
      <Shell session={session} tenant={tenant} projects={projects} current="/projects">
        <ErrorNote
          title="This project could not be read"
          detail={projectRes.error.detail}
          traceId={projectRes.error.traceId}
        />
      </Shell>
    )
  }
  const project = projectRes.data

  const byStatus = artifacts.reduce<Record<string, number>>((acc, a) => {
    acc[a.status] = (acc[a.status] ?? 0) + 1
    return acc
  }, {})
  const approved = (byStatus.APPROVED ?? 0) + (byStatus.FROZEN ?? 0)
  const awaitingReview = (byStatus.USER_REVIEW ?? 0) + (byStatus.AI_REVIEW ?? 0)
  const proposedLinks = links.filter((l) => l.status === 'PROPOSED')

  return (
    <Shell session={session} tenant={tenant} projects={projects} current="/projects">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-semibold tracking-tight">{project.name}</h1>
            <span className="rounded bg-[--color-surface-sunken] px-1.5 py-0.5 font-mono text-[11px] text-[--color-ink-muted]">
              {project.key}
            </span>
          </div>
          <p className="mt-1 max-w-2xl text-sm text-[--color-ink-muted]">{project.description || 'No description.'}</p>
        </div>
        <div className="text-right text-xs text-[--color-ink-faint]">
          <p>phase {project.pdlc_phase}</p>
          <p>graph version {project.graph_version}</p>
        </div>
      </div>

      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Artifacts" value={artifacts.length} hint="in this project's graph" />
        <Stat label="Approved" value={approved} tone={approved > 0 ? 'good' : 'neutral'} hint="sealed and immutable" />
        <Stat
          label="Awaiting review"
          value={awaitingReview}
          tone={awaitingReview > 0 ? 'warn' : 'neutral'}
          hint="needs a reviewer who did not author it"
        />
        <Stat
          label="Links to disposition"
          value={proposedLinks.length}
          tone={proposedLinks.length > 0 ? 'warn' : 'neutral'}
          hint="proposed edges awaiting a human decision"
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Artifacts" description="The governed graph for this project." className="lg:col-span-2">
          {'error' in artifactsRes ? (
            <ErrorNote title="Artifacts could not be listed" detail={artifactsRes.error.detail} />
          ) : artifacts.length === 0 ? (
            <EmptyState
              title="No artifacts yet"
              hint="Artifacts enter the graph as drafts, move through review, and become immutable when approved."
            />
          ) : (
            <Table head={['Identifier', 'Title', 'Type', 'Status', 'Updated']}>
              {artifacts.map((a) => (
                <Row key={a.artifact_id}>
                  <Cell>
                    <Link
                      href={`/projects/${projectId}/artifacts/${encodeURIComponent(a.artifact_id)}`}
                      className="font-mono text-xs font-medium text-[--color-accent] hover:underline"
                    >
                      {a.artifact_id}
                    </Link>
                  </Cell>
                  <Cell wrap className="max-w-xs truncate text-sm">{a.title}</Cell>
                  <Cell className="text-xs text-[--color-ink-muted]">{a.artifact_type}</Cell>
                  <Cell>
                    <StatusBadge status={a.status as ArtifactStatus} />
                  </Cell>
                  <Cell>
                    <Time value={a.updated_at} />
                  </Cell>
                </Row>
              ))}
            </Table>
          )}
        </Card>

        <Card
          title="Trace links"
          description="Model-proposed edges cannot be accepted without a recorded human decision."
        >
          {'error' in linksRes ? (
            <ErrorNote title="Links could not be listed" detail={linksRes.error.detail} />
          ) : links.length === 0 ? (
            <EmptyState title="No links yet" hint="Links are what make the graph traceable in both directions." />
          ) : (
            <ul className="space-y-2.5">
              {links.slice(0, 12).map((l) => (
                <li key={l.link_id} className="rounded-lg border border-[--color-border-subtle] px-3 py-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <p className="font-mono text-[11px] leading-relaxed text-[--color-ink-muted]">
                      {l.from.artifact_id}
                      <span className="mx-1 text-[--color-ink-faint]">→</span>
                      {l.to.artifact_id}
                    </p>
                    <LinkStatusBadge status={l.status} origin={l.origin} />
                  </div>
                  <p className="mt-1 text-[11px] text-[--color-ink-faint]">
                    {l.link_type}
                    {l.origin !== 'HUMAN' && ` · confidence ${l.confidence.toFixed(2)}`}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </Shell>
  )
}
