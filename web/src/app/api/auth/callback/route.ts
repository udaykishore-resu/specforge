import { NextResponse, type NextRequest } from 'next/server'

import { decodeUnverified, exchangeCode } from '@/lib/oidc'
import { saveSession, takeFlow, type Session } from '@/lib/session'
import { publicUrl } from '@/lib/urls'

/**
 * Completes the sign-in flow.
 *
 * Three checks happen before a session is created, and each closes a specific
 * attack: the state must match the one this browser started with (CSRF on the
 * callback), the flow cookie is consumed on use (replay), and the id token's
 * nonce must match (token injection). Any failure ends at the login page with
 * no session created.
 */
export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams

  const fail = (reason: string) =>
    NextResponse.redirect(publicUrl(request, `/login?error=${encodeURIComponent(reason)}`))

  const providerError = params.get('error')
  if (providerError) {
    return fail(params.get('error_description') ?? providerError)
  }

  const code = params.get('code')
  const state = params.get('state')
  if (!code || !state) return fail('The identity provider did not return an authorization code.')

  const flow = await takeFlow()
  if (!flow) return fail('The sign-in attempt expired. Please try again.')
  if (flow.state !== state) return fail('The sign-in response did not match this browser session.')

  let tokens
  try {
    tokens = await exchangeCode(code, flow.codeVerifier)
  } catch (err) {
    return fail(err instanceof Error ? err.message : 'The token exchange failed.')
  }

  const claims = decodeUnverified(tokens.id_token ?? tokens.access_token)
  if (!claims) return fail('The identity provider returned a token that could not be read.')

  if (tokens.id_token) {
    const idClaims = decodeUnverified(tokens.id_token)
    if (!idClaims || idClaims.nonce !== flow.nonce) {
      return fail('The identity token did not match this sign-in request.')
    }
  }

  const tenantClaim = process.env.SPECFORGE_TENANT_CLAIM ?? 'tenant_id'
  const rolesClaim = process.env.SPECFORGE_ROLES_CLAIM ?? 'roles'

  const rawRoles = claims[rolesClaim]
  const roles = Array.isArray(rawRoles) ? rawRoles.filter((r): r is string => typeof r === 'string') : []

  const session: Session = {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    idToken: tokens.id_token,
    expiresAt: Math.floor(Date.now() / 1000) + (tokens.expires_in || 3600),
    subject: claims.sub,
    tenantId: typeof claims[tenantClaim] === 'string' ? (claims[tenantClaim] as string) : '',
    display: claims.name ?? claims.preferred_username ?? claims.email ?? claims.sub,
    // These claims are for rendering only. Every authorization decision is made
    // by the platform API, which verifies the token's signature; the console
    // never grants itself access by reading its own copy of the roles.
    roles,
    authTime: typeof claims.auth_time === 'number' ? claims.auth_time : Math.floor(Date.now() / 1000),
    amr: Array.isArray(claims.amr) ? claims.amr.filter((m): m is string => typeof m === 'string') : [],
  }

  await saveSession(session)
  return NextResponse.redirect(publicUrl(request, flow.returnTo))
}
