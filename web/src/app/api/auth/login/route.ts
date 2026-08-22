import { NextResponse, type NextRequest } from 'next/server'

import { authorizeUrl, challengeFor, newVerifier, randomState } from '@/lib/oidc'
import { saveFlow } from '@/lib/session'
import { publicUrl } from '@/lib/urls'

/**
 * Starts the sign-in flow.
 *
 * The PKCE verifier, the state and the nonce are generated here and stored in
 * an encrypted, http-only cookie. None of them are put in the URL beyond what
 * the protocol requires, and the verifier never leaves the server at all.
 */
export async function GET(request: NextRequest) {
  const requested = request.nextUrl.searchParams.get('returnTo') ?? '/'

  // Only same-site paths are accepted as a return target. Echoing an
  // attacker-supplied absolute URL back into a redirect after authentication is
  // how an open redirect becomes a credential-phishing page that starts on the
  // real domain.
  const returnTo = requested.startsWith('/') && !requested.startsWith('//') ? requested : '/'

  const verifier = newVerifier()
  const state = randomState()
  const nonce = randomState()

  await saveFlow({ state, nonce, codeVerifier: verifier, returnTo })

  try {
    const url = await authorizeUrl({ state, nonce, challenge: challengeFor(verifier) })
    return NextResponse.redirect(url)
  } catch (err) {
    const message = err instanceof Error ? err.message : 'the identity provider is unreachable'
    return NextResponse.redirect(publicUrl(request, `/login?error=${encodeURIComponent(message)}`))
  }
}
