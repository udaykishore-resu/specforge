import Link from 'next/link'
import type { ReactNode } from 'react'

import type { Session } from '@/lib/session'
import type { Project, Tenant } from '@/lib/types'

/**
 * The application shell: navigation, tenant context and the session menu.
 *
 * The tenant is displayed prominently and always. In a multi-tenant governance
 * tool, "which tenant am I looking at?" is never a question a reviewer should
 * have to answer by reading the URL.
 */

interface NavItem {
  href: string
  label: string
  icon: ReactNode
}

export function Shell({
  session,
  tenant,
  projects,
  current,
  children,
}: {
  session: Session
  tenant?: Tenant
  projects?: Project[]
  current?: string
  children: ReactNode
}) {
  const nav: NavItem[] = [
    { href: '/', label: 'Overview', icon: <GridIcon /> },
    { href: '/projects', label: 'Projects', icon: <LayersIcon /> },
    { href: '/tenants', label: 'Tenants', icon: <BuildingIcon /> },
    { href: '/audit', label: 'Audit trail', icon: <ShieldIcon /> },
  ]

  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-[--color-border-subtle] bg-[--color-surface] lg:flex">
        <div className="px-5 py-5">
          <Link href="/" className="flex items-center gap-2">
            <Mark />
            <span className="text-sm font-semibold tracking-tight">SpecForge</span>
          </Link>
        </div>

        <nav className="flex-1 px-3">
          <ul className="space-y-0.5">
            {nav.map((item) => {
              const active = current === item.href
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    aria-current={active ? 'page' : undefined}
                    className={`flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm transition-colors ${
                      active
                        ? 'bg-[--color-accent-soft] font-medium text-[--color-accent]'
                        : 'text-[--color-ink-muted] hover:bg-[--color-surface-raised] hover:text-[--color-ink]'
                    }`}
                  >
                    {item.icon}
                    {item.label}
                  </Link>
                </li>
              )
            })}
          </ul>

          {projects && projects.length > 0 && (
            <div className="mt-6">
              <p className="px-2.5 text-[11px] font-medium uppercase tracking-wide text-[--color-ink-faint]">
                Projects
              </p>
              <ul className="mt-1.5 space-y-0.5">
                {projects.slice(0, 8).map((p) => (
                  <li key={p.project_id}>
                    <Link
                      href={`/projects/${p.project_id}`}
                      className="flex items-center justify-between gap-2 rounded-md px-2.5 py-1.5 text-sm text-[--color-ink-muted] hover:bg-[--color-surface-raised] hover:text-[--color-ink]"
                    >
                      <span className="truncate">{p.name}</span>
                      <span className="font-mono text-[10px] text-[--color-ink-faint]">{p.key}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </nav>

        <div className="border-t border-[--color-border-subtle] px-3 py-3">
          <div className="rounded-md px-2.5 py-2">
            <p className="truncate text-sm font-medium">{session.display}</p>
            <p className="mt-0.5 truncate text-xs text-[--color-ink-faint]">
              {session.roles.length > 0 ? session.roles.join(', ') : 'no roles granted'}
            </p>
          </div>
          <form action="/api/auth/logout" method="post">
            <button
              type="submit"
              className="mt-1 w-full rounded-md px-2.5 py-1.5 text-left text-xs text-[--color-ink-muted] hover:bg-[--color-surface-raised] hover:text-[--color-ink]"
            >
              Sign out
            </button>
          </form>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-4 border-b border-[--color-border-subtle] bg-[--color-surface] px-6 py-3">
          <div className="flex min-w-0 items-center gap-3">
            <Link href="/" className="lg:hidden">
              <Mark />
            </Link>
            {tenant ? (
              <div className="flex min-w-0 items-center gap-2">
                <span className="truncate text-sm font-medium">{tenant.name}</span>
                <span className="rounded bg-[--color-surface-sunken] px-1.5 py-0.5 font-mono text-[11px] text-[--color-ink-muted]">
                  {tenant.slug}
                </span>
                {tenant.status !== 'ACTIVE' && (
                  <span className="rounded bg-[--color-danger-soft] px-1.5 py-0.5 text-[11px] font-medium text-[--color-danger]">
                    {tenant.status}
                  </span>
                )}
              </div>
            ) : (
              <span className="text-sm text-[--color-ink-faint]">No tenant context</span>
            )}
          </div>

          <div className="flex items-center gap-3 text-xs text-[--color-ink-faint]">
            {session.amr.length > 0 && (
              <span title="Authentication methods presented at sign-in">amr: {session.amr.join('+')}</span>
            )}
          </div>
        </header>

        <main className="flex-1 px-6 py-6">{children}</main>
      </div>
    </div>
  )
}

function Mark() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true">
      <rect x="1.5" y="1.5" width="17" height="17" rx="4.5" stroke="currentColor" strokeWidth="1.4" opacity="0.35" />
      <path d="M6 10.5l2.6 2.6L14 7.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function GridIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <rect x="2" y="2" width="5" height="5" rx="1.2" stroke="currentColor" strokeWidth="1.3" />
      <rect x="9" y="2" width="5" height="5" rx="1.2" stroke="currentColor" strokeWidth="1.3" />
      <rect x="2" y="9" width="5" height="5" rx="1.2" stroke="currentColor" strokeWidth="1.3" />
      <rect x="9" y="9" width="5" height="5" rx="1.2" stroke="currentColor" strokeWidth="1.3" />
    </svg>
  )
}

function LayersIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 2l6 3-6 3-6-3 6-3z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
      <path d="M2 8l6 3 6-3" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
      <path d="M2 11.5l6 3 6-3" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
    </svg>
  )
}

function BuildingIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <rect x="3" y="2" width="10" height="12" rx="1.2" stroke="currentColor" strokeWidth="1.3" />
      <path d="M6 5h1M9 5h1M6 8h1M9 8h1M6 11h4" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    </svg>
  )
}

function ShieldIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 2l5 2v4.2c0 3-2.1 5.2-5 6-2.9-.8-5-3-5-6V4l5-2z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
      <path d="M5.8 8.2l1.6 1.6 3-3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}
