import Link from 'next/link'

import { Shell } from '@/components/shell'
import { Card, Cell, EmptyState, ErrorNote, Hash, Row, SeverityBadge, Stat, Table, Time } from '@/components/ui'
import { api, attempt } from '@/lib/api'
import { requireSession } from '@/lib/guard'

export const dynamic = 'force-dynamic'

/**
 * The overview.
 *
 * The integrity panel is first and largest on purpose. Everything else on this
 * page is activity; that panel is the answer to "can I still trust what this
 * system is telling me?", and it should be readable without scrolling.
 */
export default async function OverviewPage() {
  const session = await requireSession('/')
  const tenantId = session.tenantId

  const [tenantRes, projectsRes, auditRes, verifyRes] = await Promise.all([
    attempt(() => api.tenant(tenantId)),
    attempt(() => api.projects(tenantId)),
    attempt(() => api.audit(tenantId, { limit: 12 })),
    attempt(() => api.verifyAudit(tenantId)),
  ])

  const tenant = 'data' in tenantRes ? tenantRes.data : undefined
  const projects = 'data' in projectsRes ? projectsRes.data.items : []
  const records = 'data' in auditRes ? auditRes.data.items : []
  const verify = 'data' in verifyRes ? verifyRes.data : undefined

  return (
    <Shell session={session} tenant={tenant} projects={projects} current="/">
      <div className="mb-6">
        <h1 className="text-xl font-semibold tracking-tight">Overview</h1>
        <p className="mt-1 text-sm text-[--color-ink-muted]">
          Governance state for {tenant?.name ?? 'this tenant'}.
        </p>
      </div>

      {!tenantId && (
        <div className="mb-6">
          <ErrorNote
            title="Your token carries no tenant"
            detail="The identity provider did not return a tenant claim, so there is nothing to scope this session to. Ask an administrator to map your account to a tenant."
          />
        </div>
      )}

      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Stat
          label="Audit chain"
          value={verify ? (verify.valid ? 'Verified' : 'BROKEN') : '—'}
          tone={verify ? (verify.valid ? 'good' : 'bad') : 'neutral'}
          hint={
            verify
              ? verify.valid
                ? `${verify.records_checked} records${verify.anchored_at ? `, anchored at ${verify.anchored_at}` : ', not yet anchored'}`
                : (verify.reason ?? `diverges at sequence ${verify.failed_at}`)
              : 'unavailable'
          }
        />
        <Stat label="Projects" value={projects.length} hint="active in this tenant" />
        <Stat
          label="Audit records"
          value={verify?.records_checked ?? records.length}
          hint="append-only, hash-chained"
        />
        <Stat
          label="Isolation"
          value={tenant?.isolation_mode ?? '—'}
          hint="row-level security is enforced in all modes"
        />
      </div>

      {verify && !verify.valid && (
        <div className="mb-6">
          <ErrorNote
            title="The audit chain does not verify"
            detail={`${verify.reason ?? 'A record does not link to its predecessor.'} Treat this as a suspected tampering incident: preserve the database and object store before any remediation, and follow the integrity section of the operational runbook.`}
          />
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-5">
        <Card
          title="Projects"
          description="Each project owns its own artifact graph."
          className="lg:col-span-2"
        >
          {projects.length === 0 ? (
            <EmptyState
              title="No projects yet"
              hint="A project scopes an artifact graph: requirements, specifications, architecture and the trace links between them."
            />
          ) : (
            <ul className="space-y-1">
              {projects.map((p) => (
                <li key={p.project_id}>
                  <Link
                    href={`/projects/${p.project_id}`}
                    className="flex items-center justify-between gap-3 rounded-lg px-3 py-2.5 hover:bg-[--color-surface-raised]"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium">{p.name}</p>
                      <p className="truncate text-xs text-[--color-ink-muted]">{p.description || '—'}</p>
                    </div>
                    <div className="shrink-0 text-right">
                      <p className="font-mono text-xs text-[--color-ink-muted]">{p.key}</p>
                      <p className="text-[11px] text-[--color-ink-faint]">graph v{p.graph_version}</p>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card
          title="Recent activity"
          description="Every entry is hash-chained to the one before it."
          className="lg:col-span-3"
          action={
            <Link href="/audit" className="text-xs font-medium text-[--color-accent] hover:underline">
              Full trail
            </Link>
          }
        >
          {'error' in auditRes ? (
            <ErrorNote
              title="The audit trail could not be read"
              detail={auditRes.error.detail}
              traceId={auditRes.error.traceId}
            />
          ) : records.length === 0 ? (
            <EmptyState title="Nothing recorded yet" hint="Audit entries appear as soon as anything is created or approved." />
          ) : (
            <Table head={['Seq', 'Action', 'When', 'Hash']}>
              {records.map((r) => (
                <Row key={r.sequence}>
                  <Cell className="font-mono text-xs text-[--color-ink-faint]">{r.sequence}</Cell>
                  <Cell>
                    <div className="flex items-center gap-2">
                      <span className="text-sm">{r.action}</span>
                      <SeverityBadge severity={r.severity} outcome={r.outcome} />
                    </div>
                  </Cell>
                  <Cell>
                    <Time value={r.occurred_at} />
                  </Cell>
                  <Cell>
                    <Hash value={r.record_hash} />
                  </Cell>
                </Row>
              ))}
            </Table>
          )}
        </Card>
      </div>
    </Shell>
  )
}
