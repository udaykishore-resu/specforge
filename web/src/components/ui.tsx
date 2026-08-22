import type { ReactNode } from 'react'

import type { ArtifactStatus, LinkStatus, Outcome, Severity } from '@/lib/types'

/**
 * The shared presentational vocabulary.
 *
 * State is the thing this console exists to communicate, so state has exactly
 * one visual treatment across every page. A reviewer should recognise APPROVED
 * without reading the word.
 */

export function Card({
  title,
  description,
  action,
  children,
  className = '',
}: {
  title?: string
  description?: string
  action?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`sf-card ${className}`}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-4 border-b border-[--color-border-subtle] px-5 py-4">
          <div>
            {title && <h2 className="text-sm font-semibold tracking-tight text-[--color-ink]">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-[--color-ink-muted]">{description}</p>}
          </div>
          {action}
        </header>
      )}
      <div className="px-5 py-4">{children}</div>
    </section>
  )
}

const artifactTone: Record<ArtifactStatus, { bg: string; fg: string; label: string }> = {
  DRAFT: { bg: 'bg-[--color-draft-soft]', fg: 'text-[--color-draft]', label: 'Draft' },
  AI_REVIEW: { bg: 'bg-[--color-accent-soft]', fg: 'text-[--color-accent]', label: 'AI review' },
  USER_REVIEW: { bg: 'bg-[--color-review-soft]', fg: 'text-[--color-review]', label: 'In review' },
  CHANGES_REQUESTED: { bg: 'bg-[--color-review-soft]', fg: 'text-[--color-review]', label: 'Changes requested' },
  APPROVED: { bg: 'bg-[--color-sealed-soft]', fg: 'text-[--color-sealed]', label: 'Approved' },
  FROZEN: { bg: 'bg-[--color-sealed-soft]', fg: 'text-[--color-sealed]', label: 'Frozen' },
  SUPERSEDED: { bg: 'bg-[--color-draft-soft]', fg: 'text-[--color-ink-faint]', label: 'Superseded' },
  ABANDONED: { bg: 'bg-[--color-draft-soft]', fg: 'text-[--color-ink-faint]', label: 'Abandoned' },
}

export function StatusBadge({ status }: { status: ArtifactStatus }) {
  const tone = artifactTone[status] ?? artifactTone.DRAFT
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${tone.bg} ${tone.fg}`}
    >
      {(status === 'APPROVED' || status === 'FROZEN') && <SealIcon />}
      {tone.label}
    </span>
  )
}

export function LinkStatusBadge({ status, origin }: { status: LinkStatus; origin?: string }) {
  const tone =
    status === 'ACCEPTED'
      ? 'bg-[--color-sealed-soft] text-[--color-sealed]'
      : status === 'REJECTED'
        ? 'bg-[--color-danger-soft] text-[--color-danger]'
        : status === 'STALE'
          ? 'bg-[--color-draft-soft] text-[--color-ink-faint]'
          : 'bg-[--color-review-soft] text-[--color-review]'

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${tone}`}>
      {origin === 'LLM_PROPOSED' && <span title="Proposed by a model">◆</span>}
      {status.toLowerCase()}
    </span>
  )
}

export function SeverityBadge({ severity, outcome }: { severity: Severity; outcome: Outcome }) {
  const tone =
    outcome === 'DENIED' || severity === 'CRITICAL'
      ? 'bg-[--color-danger-soft] text-[--color-danger]'
      : severity === 'WARNING'
        ? 'bg-[--color-review-soft] text-[--color-review]'
        : 'bg-[--color-draft-soft] text-[--color-ink-muted]'

  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide ${tone}`}>
      {outcome === 'SUCCESS' ? severity : outcome}
    </span>
  )
}

function SealIcon() {
  return (
    <svg width="10" height="10" viewBox="0 0 12 12" fill="none" aria-hidden="true">
      <path
        d="M6 1l1.5 1.1 1.85-.15.5 1.79 1.4 1.22-1.02 1.56.28 1.83-1.8.5-1.16 1.44L6 9.6l-1.55.69L3.29 8.85l-1.8-.5.28-1.83L.75 4.96l1.4-1.22.5-1.79L4.5 2.1 6 1z"
        fill="currentColor"
        opacity="0.9"
      />
    </svg>
  )
}

/**
 * Renders a content hash.
 *
 * Truncated for reading, complete in the title attribute and selectable in
 * full, because the reason a hash is on screen at all is so someone can compare
 * it with one from somewhere else.
 */
export function Hash({ value, full = false }: { value: string; full?: boolean }) {
  if (!value) return <span className="sf-hash">—</span>
  const shown = full ? value : value.replace(/^sha256:/, '').slice(0, 12)
  return (
    <code className="sf-hash" title={value}>
      {full ? shown : `${shown}…`}
    </code>
  )
}

export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-[--color-border-subtle] px-6 py-10 text-center">
      <p className="text-sm font-medium text-[--color-ink]">{title}</p>
      {hint && <p className="max-w-md text-xs text-[--color-ink-muted]">{hint}</p>}
      {action}
    </div>
  )
}

export function ErrorNote({ title, detail, traceId }: { title: string; detail?: string; traceId?: string }) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-[--color-danger] bg-[--color-danger-soft] px-4 py-3 text-sm text-[--color-danger]"
    >
      <p className="font-medium">{title}</p>
      {detail && <p className="mt-1 text-xs opacity-90">{detail}</p>}
      {traceId && <p className="mt-1 font-mono text-[11px] opacity-70">trace {traceId}</p>}
    </div>
  )
}

export function Stat({
  label,
  value,
  hint,
  tone = 'neutral',
}: {
  label: string
  value: string | number
  hint?: string
  tone?: 'neutral' | 'good' | 'warn' | 'bad'
}) {
  const toneClass =
    tone === 'good'
      ? 'text-[--color-sealed]'
      : tone === 'warn'
        ? 'text-[--color-review]'
        : tone === 'bad'
          ? 'text-[--color-danger]'
          : 'text-[--color-ink]'

  return (
    <div className="sf-card px-5 py-4">
      <p className="text-xs font-medium uppercase tracking-wide text-[--color-ink-faint]">{label}</p>
      <p className={`mt-1.5 text-2xl font-semibold tabular-nums ${toneClass}`}>{value}</p>
      {hint && <p className="mt-1 text-xs text-[--color-ink-muted]">{hint}</p>}
    </div>
  )
}

export function Table({ head, children }: { head: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[36rem] border-collapse text-sm">
        <thead>
          <tr className="border-b border-[--color-border-subtle]">
            {head.map((h) => (
              <th
                key={h}
                className="px-3 py-2 text-left text-xs font-medium uppercase tracking-wide text-[--color-ink-faint]"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

export function Row({ children }: { children: ReactNode }) {
  return <tr className="border-b border-[--color-border-subtle] last:border-0 hover:bg-[--color-surface-raised]">{children}</tr>
}

export function Cell({
  children,
  className = '',
  wrap = false,
}: {
  children: ReactNode
  className?: string
  /** Allow the cell to wrap. Identifiers, hashes and timestamps must not. */
  wrap?: boolean
}) {
  return (
    <td className={`px-3 py-2.5 align-middle ${wrap ? '' : 'whitespace-nowrap'} ${className}`}>{children}</td>
  )
}

export function Time({ value }: { value?: string }) {
  if (!value) return <span className="text-[--color-ink-faint]">—</span>
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return <span className="text-[--color-ink-faint]">—</span>
  return (
    <time dateTime={value} title={date.toISOString()} className="tabular-nums text-xs text-[--color-ink-muted]">
      {date.toISOString().replace('T', ' ').slice(0, 19)}Z
    </time>
  )
}
