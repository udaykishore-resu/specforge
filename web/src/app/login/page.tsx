import { redirect } from 'next/navigation'

import { readSession } from '@/lib/session'

export const dynamic = 'force-dynamic'

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; signedOut?: string; returnTo?: string }>
}) {
  const session = await readSession()
  if (session) redirect('/')

  const params = await searchParams
  const returnTo = params.returnTo && params.returnTo.startsWith('/') ? params.returnTo : '/'

  return (
    <div className="flex min-h-screen items-center justify-center px-6">
      <div className="w-full max-w-sm">
        <div className="sf-card px-6 py-7">
          <h1 className="text-lg font-semibold tracking-tight">SpecForge</h1>
          <p className="mt-1 text-sm text-[--color-ink-muted]">
            Sign in with your organization&rsquo;s identity provider.
          </p>

          {params.error && (
            <div
              role="alert"
              className="mt-4 rounded-lg border border-[--color-danger] bg-[--color-danger-soft] px-3 py-2 text-xs text-[--color-danger]"
            >
              {params.error}
            </div>
          )}
          {params.signedOut && !params.error && (
            <p className="mt-4 rounded-lg bg-[--color-surface-sunken] px-3 py-2 text-xs text-[--color-ink-muted]">
              You have been signed out.
            </p>
          )}

          {/*
            A plain anchor, deliberately, not next/link. The sign-in route
            answers with a cross-origin redirect to the identity provider, and a
            client-side navigation would try to fetch it as an RSC payload —
            which the content security policy refuses, and which would also
            invoke the route on prefetch and quietly replace the PKCE verifier
            of a sign-in already in progress. Authentication needs a real
            browser navigation.
          */}
          <a
            href={`/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`}
            className="mt-5 flex w-full items-center justify-center rounded-lg bg-[--color-accent] px-4 py-2.5 text-sm font-medium text-white transition-opacity hover:opacity-90"
          >
            Continue
          </a>

          <p className="mt-5 text-[11px] leading-relaxed text-[--color-ink-faint]">
            Authentication uses the authorization-code flow with PKCE. Your access token stays on the
            server; the browser only ever holds an encrypted session cookie.
          </p>
        </div>
      </div>
    </div>
  )
}
