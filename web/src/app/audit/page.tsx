import { Shell } from '@/components/shell'
import { Card, Cell, EmptyState, ErrorNote, Hash, Row, SeverityBadge, Table, Time } from '@/components/ui'
import { api, attempt } from '@/lib/api'
import { requireSession } from '@/lib/guard'

export const dynamic = 'force-dynamic'

/**
 * The audit trail.
 *
 * Both chain hashes are shown for every record, not hidden behind a detail
 * view. The point of a hash-chained trail is that someone outside the platform
 * can recompute it; a trail whose hashes are only visible to the system that
 * produced them proves nothing.
 */
export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ action?: string; severity?: string }>
}) {
  const session = await requireSession('/audit')
  const filters = await searchParams
  const tenantId = session.tenantId

  const [tenantRes, projectsRes, auditRes, verifyRes] = await Promise.all([
    attempt(() => api.tenant(tenantId)),
    attempt(() => api.projects(tenantId)),
    attempt(() => api.audit(tenantId, { action: filters.action, severity: filters.severity, limit: 100 })),
    attempt(() => api.verifyAudit(tenantId)),
  ])

  const tenant = 'data' in tenantRes ? tenantRes.data : undefined
  const projects = 'data' in projectsRes ? projectsRes.data.items : []
  const records = 'data' in auditRes ? auditRes.data.items : []
  const verify = 'data' in verifyRes ? verifyRes.data : undefined

  return (
    <Shell session={session} tenant={tenant} projects={projects} current="/audit">
      <div className="mb-6">
        <h1 className="text-xl font-semibold tracking-tight">Audit trail</h1>
        <p className="mt-1 max-w-3xl text-sm text-[--color-ink-muted]">
          Append-only and hash-chained per tenant. Each record commits in the same transaction as the
          change it describes, so an operation that failed to audit could not have succeeded.
        </p>
      </div>

      <div className="mb-6">
        {verify ? (
          <div
            className={`rounded-lg border px-4 py-3 ${
              verify.valid
                ? 'border-[--color-sealed] bg-[--color-sealed-soft]'
                : 'border-[--color-danger] bg-[--color-danger-soft]'
            }`}
          >
            <p
              className={`text-sm font-medium ${
                verify.valid ? 'text-[--color-sealed]' : 'text-[--color-danger]'
              }`}
            >
              {verify.valid
                ? `Chain verified — ${verify.records_checked} records, sequences ${verify.from} to ${verify.to}`
                : `Chain INVALID at sequence ${verify.failed_at}`}
            </p>
            <p
              className={`mt-1 text-xs ${verify.valid ? 'text-[--color-sealed]' : 'text-[--color-danger]'} opacity-90`}
            >
              {verify.valid
                ? verify.anchored_at
                  ? `Compared against the anchor published at sequence ${verify.anchored_at}. An anchor is written to object-lock storage, so a rewrite of history could not also rewrite it.`
                  : 'No anchor has been published yet, so this confirms internal consistency only. The worker publishes anchors hourly.'
                : (verify.reason ?? 'A record does not link to its predecessor.')}
            </p>
          </div>
        ) : (
          <ErrorNote
            title="Chain verification is unavailable"
            detail={'error' in verifyRes ? verifyRes.error.detail : undefined}
          />
        )}
      </div>

      <Card
        title="Records"
        description={
          filters.action || filters.severity
            ? `Filtered${filters.action ? ` by action ${filters.action}` : ''}${filters.severity ? ` at severity ${filters.severity}` : ''}.`
            : 'Most recent first.'
        }
      >
        {'error' in auditRes ? (
          <ErrorNote title="The trail could not be read" detail={auditRes.error.detail} traceId={auditRes.error.traceId} />
        ) : records.length === 0 ? (
          <EmptyState title="No records match" hint="Audit entries are written for every governed operation, including refusals." />
        ) : (
          <Table head={['Seq', 'Action', 'Actor', 'When', 'Previous', 'Record']}>
            {records.map((r) => (
              <Row key={r.sequence}>
                <Cell className="font-mono text-xs text-[--color-ink-faint]">{r.sequence}</Cell>
                <Cell>
                  <div className="flex items-center gap-2">
                    <span className="text-sm">{r.action}</span>
                    <SeverityBadge severity={r.severity} outcome={r.outcome} />
                  </div>
                </Cell>
                <Cell className="font-mono text-[11px] text-[--color-ink-muted]">{actorLabel(r.actor)}</Cell>
                <Cell>
                  <Time value={r.occurred_at} />
                </Cell>
                <Cell>
                  <Hash value={r.prev_hash} />
                </Cell>
                <Cell>
                  <Hash value={r.record_hash} />
                </Cell>
              </Row>
            ))}
          </Table>
        )}
      </Card>

      <p className="mt-4 text-[11px] leading-relaxed text-[--color-ink-faint]">
        To verify independently of this console:{' '}
        <code className="font-mono text-[--color-ink-muted]">specforge-cli verify-audit --tenant {tenantId}</code>. It
        recomputes every hash from the stored records and exits non-zero on a broken chain, which makes it
        usable as a scheduled check.
      </p>
    </Shell>
  )
}

function actorLabel(actor?: Record<string, unknown>): string {
  if (!actor) return '—'
  const display = actor.display ?? actor.principal_id ?? actor.id
  if (typeof display !== 'string') return '—'
  return display.length > 20 ? `${display.slice(0, 18)}…` : display
}
