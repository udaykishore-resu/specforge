import { NextResponse, type NextRequest } from 'next/server'

import { endSessionUrl } from '@/lib/oidc'
import { clearSession, readSession } from '@/lib/session'
import { publicUrl } from '@/lib/urls'

/**
 * Ends the session.
 *
 * The local cookie is cleared first and unconditionally. If the provider's
 * end-session call then fails, the user is still signed out here, which is the
 * outcome they asked for; the reverse order would leave a live session behind
 * on a network error.
 */
export async function POST(request: NextRequest) {
  const session = await readSession()
  await clearSession()

  try {
    const url = await endSessionUrl(session?.idToken)
    if (url) return NextResponse.redirect(url, { status: 303 })
  } catch {
    // The provider is unreachable. The local session is already gone.
  }
  return NextResponse.redirect(publicUrl(request, '/login?signedOut=1'), { status: 303 })
}
