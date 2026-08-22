import 'server-only'

import { createHash, randomBytes } from 'node:crypto'

/**
 * The OIDC authorization-code flow with PKCE, implemented against the issuer's
 * discovery document.
 *
 * PKCE is used even though this is a confidential client with a server-side
 * secret. The reason is that the code is the credential in flight: with S256
 * binding, an intercepted code is useless without the verifier that never left
 * the server, and that holds regardless of what happens to the client secret.
 */

export interface Discovery {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  userinfo_endpoint?: string
  end_session_endpoint?: string
  code_challenge_methods_supported?: string[]
}

interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
  refresh_token?: string
  id_token?: string
}

export interface Claims {
  sub: string
  exp: number
  iat: number
  auth_time?: number
  nonce?: string
  amr?: string[]
  name?: string
  preferred_username?: string
  email?: string
  [claim: string]: unknown
}

let cached: { at: number; doc: Discovery } | null = null

function issuerUrl(): string {
  const issuer = process.env.SPECFORGE_ISSUER_URL
  if (!issuer) throw new Error('SPECFORGE_ISSUER_URL is not set')
  return issuer.replace(/\/$/, '')
}

export async function discover(): Promise<Discovery> {
  // Ten minutes is short enough to pick up an issuer rotation without a
  // redeploy and long enough that the discovery endpoint is not in the hot path
  // of every sign-in.
  if (cached && Date.now() - cached.at < 600_000) return cached.doc

  const res = await fetch(`${issuerUrl()}/.well-known/openid-configuration`, {
    cache: 'no-store',
  })
  if (!res.ok) {
    throw new Error(`OIDC discovery failed with status ${res.status}`)
  }
  const doc = (await res.json()) as Discovery

  if (doc.issuer.replace(/\/$/, '') !== issuerUrl()) {
    // A discovery document that names a different issuer is either
    // misconfiguration or redirection to an attacker's provider. Neither is
    // something to proceed through.
    throw new Error(
      `the discovery document declares issuer ${doc.issuer}, which does not match the configured issuer`,
    )
  }

  cached = { at: Date.now(), doc }
  return doc
}

export function newVerifier(): string {
  return randomBytes(48).toString('base64url')
}

export function challengeFor(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url')
}

export function randomState(): string {
  return randomBytes(24).toString('base64url')
}

export function clientId(): string {
  const id = process.env.SPECFORGE_CLIENT_ID
  if (!id) throw new Error('SPECFORGE_CLIENT_ID is not set')
  return id
}

export function redirectUri(): string {
  const uri = process.env.SPECFORGE_REDIRECT_URL
  if (!uri) throw new Error('SPECFORGE_REDIRECT_URL is not set')
  return uri
}

export async function authorizeUrl(params: {
  state: string
  nonce: string
  challenge: string
}): Promise<string> {
  const doc = await discover()

  if (doc.code_challenge_methods_supported && !doc.code_challenge_methods_supported.includes('S256')) {
    // Falling back to `plain` would defeat the purpose. Refusing is the correct
    // response to a provider that cannot do PKCE properly.
    throw new Error('the identity provider does not support S256 PKCE')
  }

  const url = new URL(doc.authorization_endpoint)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', clientId())
  url.searchParams.set('redirect_uri', redirectUri())
  url.searchParams.set('scope', 'openid profile email offline_access')
  url.searchParams.set('state', params.state)
  url.searchParams.set('nonce', params.nonce)
  url.searchParams.set('code_challenge', params.challenge)
  url.searchParams.set('code_challenge_method', 'S256')
  return url.toString()
}

/**
 * Builds the authorize URL for a step-up: same flow, but the provider is asked
 * to re-authenticate with a second factor.
 */
export async function stepUpUrl(params: {
  state: string
  nonce: string
  challenge: string
}): Promise<string> {
  const base = new URL(await authorizeUrl(params))
  base.searchParams.set('prompt', 'login')
  base.searchParams.set('acr_values', 'mfa')
  base.searchParams.set('max_age', '0')
  return base.toString()
}

export async function exchangeCode(code: string, verifier: string): Promise<TokenResponse> {
  const doc = await discover()

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectUri(),
    client_id: clientId(),
    code_verifier: verifier,
  })

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  }
  const secret = process.env.SPECFORGE_CLIENT_SECRET
  if (secret) {
    headers.Authorization =
      'Basic ' + Buffer.from(`${encodeURIComponent(clientId())}:${encodeURIComponent(secret)}`).toString('base64')
  }

  const res = await fetch(doc.token_endpoint, { method: 'POST', headers, body, cache: 'no-store' })
  if (!res.ok) {
    const detail = await res.text()
    throw new Error(`token exchange failed with status ${res.status}: ${detail.slice(0, 200)}`)
  }
  return (await res.json()) as TokenResponse
}

/**
 * Decodes a JWT payload without verifying it.
 *
 * This is used only to read claims out of a token the platform API will verify
 * for itself on every call. The console never makes an authorization decision
 * from these claims — it uses them to render a name and to decide whether to
 * offer a step-up prompt. Naming the function for what it does keeps that
 * boundary visible to the next reader.
 */
export function decodeUnverified(token: string): Claims | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    return JSON.parse(Buffer.from(parts[1] as string, 'base64url').toString('utf8')) as Claims
  } catch {
    return null
  }
}

export async function endSessionUrl(idToken?: string): Promise<string | null> {
  const doc = await discover()
  if (!doc.end_session_endpoint) return null

  const url = new URL(doc.end_session_endpoint)
  if (idToken) url.searchParams.set('id_token_hint', idToken)
  const publicUrl = process.env.SPECFORGE_PUBLIC_URL ?? 'http://localhost:3000'
  url.searchParams.set('post_logout_redirect_uri', publicUrl)
  return url.toString()
}
