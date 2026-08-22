import Link from 'next/link'

import { Shell } from '@/components/shell'
import { Card, EmptyState, ErrorNote } from '@/components/ui'
import { api, attempt } from '@/lib/api'
import { requireSession } from '@/lib/guard'

export const dynamic = 'force-dynamic'

export default async function ProjectsPage() {
  const session = await requireSession('/projects')

  const [tenantRes, projectsRes] = await Promise.all([
    attempt(() => api.tenant(session.tenantId)),
    attempt(() => api.projects(session.tenantId)),
  ])

  const tenant = 'data' in tenantRes ? tenantRes.data : undefined
  const projects = 'data' in projectsRes ? projectsRes.data.items : []

  return (
    <Shell session={session} tenant={tenant} projects={projects} current="/projects">
      <div className="mb-6">
        <h1 className="text-xl font-semibold tracking-tight">Projects</h1>
        <p className="mt-1 text-sm text-[--color-ink-muted]">
          Each project holds one artifact graph and one traceability boundary.
        </p>
      </div>

      {'error' in projectsRes ? (
        <ErrorNote title="Projects could not be listed" detail={projectsRes.error.detail} traceId={projectsRes.error.traceId} />
      ) : projects.length === 0 ? (
        <Card>
          <EmptyState
            title="No projects yet"
            hint="Run `make seed` against a development database to create a worked example: an approved requirement, a specification derived from it, and the trace link between them."
          />
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {projects.map((p) => (
            <Link key={p.project_id} href={`/projects/${p.project_id}`} className="sf-card block px-5 py-4 transition-colors hover:border-[--color-border-strong]">
              <div className="flex items-start justify-between gap-3">
                <h2 className="text-sm font-semibold">{p.name}</h2>
                <span className="shrink-0 rounded bg-[--color-surface-sunken] px-1.5 py-0.5 font-mono text-[11px] text-[--color-ink-muted]">
                  {p.key}
                </span>
              </div>
              <p className="mt-1.5 line-clamp-2 text-xs text-[--color-ink-muted]">{p.description || 'No description.'}</p>
              <div className="mt-3 flex items-center gap-3 text-[11px] text-[--color-ink-faint]">
                <span>{p.status}</span>
                <span>phase {p.pdlc_phase}</span>
                <span>graph v{p.graph_version}</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </Shell>
  )
}
