import 'server-only'

import { redirect } from 'next/navigation'

import { readSession, type Session } from './session'

/**
 * Requires a session, or sends the visitor to sign in.
 *
 * Every page in the console calls this. It is not the authorization check —
 * that belongs to the platform API, which verifies the token on every request
 * and decides what this principal may do. This only establishes that there is
 * someone to make the call as.
 */
export async function requireSession(returnTo?: string): Promise<Session> {
  const session = await readSession()
  if (!session) {
    const target = returnTo && returnTo.startsWith('/') ? returnTo : undefined
    redirect(target ? `/login?returnTo=${encodeURIComponent(target)}` : '/login')
  }
  return session
}
