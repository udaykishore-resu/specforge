import { NextResponse, type NextRequest } from 'next/server'

import { challengeFor, newVerifier, randomState, stepUpUrl } from '@/lib/oidc'
import { saveFlow } from '@/lib/session'
import { publicUrl } from '@/lib/urls'

/**
 * Re-authenticates with a second factor.
 *
 * Approval requires a recent second factor, and the platform API enforces that
 * on every approval regardless of what the console does. This route exists so
 * that a reviewer who is about to approve can refresh their authentication
 * before writing a comment, instead of losing the comment to a 401.
 */
export async function GET(request: NextRequest) {
  const requested = request.nextUrl.searchParams.get('returnTo') ?? '/'
  const returnTo = requested.startsWith('/') && !requested.startsWith('//') ? requested : '/'

  const verifier = newVerifier()
  const state = randomState()
  const nonce = randomState()

  await saveFlow({ state, nonce, codeVerifier: verifier, returnTo })

  try {
    const url = await stepUpUrl({ state, nonce, challenge: challengeFor(verifier) })
    return NextResponse.redirect(url)
  } catch (err) {
    const message = err instanceof Error ? err.message : 'step-up authentication is unavailable'
    return NextResponse.redirect(publicUrl(request, `${returnTo}?stepUpError=${encodeURIComponent(message)}`))
  }
}
