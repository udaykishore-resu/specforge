import { Shell } from '@/components/shell'
import { Card, Cell, EmptyState, ErrorNote, Row, Table, Time } from '@/components/ui'
import { api, attempt } from '@/lib/api'
import { requireSession } from '@/lib/guard'

export const dynamic = 'force-dynamic'

export default async function TenantsPage() {
  const session = await requireSession('/tenants')

  const [listRes, currentRes] = await Promise.all([
    attempt(() => api.tenants()),
    attempt(() => api.tenant(session.tenantId)),
  ])

  const tenant = 'data' in currentRes ? currentRes.data : undefined
  const tenants = 'data' in listRes ? listRes.data.items : []

  return (
    <Shell session={session} tenant={tenant} current="/tenants">
      <div className="mb-6">
        <h1 className="text-xl font-semibold tracking-tight">Tenants</h1>
        <p className="mt-1 text-sm text-[--color-ink-muted]">
          A token is scoped to one tenant. This list shows what your credentials reach, which for most
          roles is a single row.
        </p>
      </div>

      <Card>
        {'error' in listRes ? (
          <ErrorNote title="Tenants could not be listed" detail={listRes.error.detail} traceId={listRes.error.traceId} />
        ) : tenants.length === 0 ? (
          <EmptyState title="No tenants visible" hint="Your role does not include tenant:read, or no tenant has been provisioned yet." />
        ) : (
          <Table head={['Name', 'Slug', 'Status', 'Isolation', 'Region', 'Created']}>
            {tenants.map((t) => (
              <Row key={t.tenant_id}>
                <Cell className="font-medium">{t.name}</Cell>
                <Cell className="font-mono text-xs text-[--color-ink-muted]">{t.slug}</Cell>
                <Cell>
                  <span
                    className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${
                      t.status === 'ACTIVE'
                        ? 'bg-[--color-sealed-soft] text-[--color-sealed]'
                        : 'bg-[--color-danger-soft] text-[--color-danger]'
                    }`}
                  >
                    {t.status}
                  </span>
                </Cell>
                <Cell className="text-xs text-[--color-ink-muted]">{t.isolation_mode}</Cell>
                <Cell className="text-xs text-[--color-ink-muted]">{t.region || '—'}</Cell>
                <Cell>
                  <Time value={t.created_at} />
                </Cell>
              </Row>
            ))}
          </Table>
        )}
      </Card>
    </Shell>
  )
}
