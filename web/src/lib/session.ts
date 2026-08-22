import 'server-only'

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes, timingSafeEqual } from 'node:crypto'
import { cookies } from 'next/headers'

/**
 * Server-side session handling.
 *
 * The design decision that matters here: the browser never receives an access
 * token. The session cookie holds the tokens, encrypted, and only the Next.js
 * server can read it. Every call to the platform API is made server-side with
 * the token attached there. An XSS on a page therefore steals a session that is
 * already scoped to that browser rather than a bearer token that would work
 * anywhere.
 *
 * The cookie is authenticated encryption (AES-256-GCM), not a signed plaintext
 * blob, so the contents are neither readable nor malleable by the client.
 */

const COOKIE_NAME = 'sf_session'
const FLOW_COOKIE = 'sf_flow'
const VERSION = 'v1'

export interface Session {
  accessToken: string
  refreshToken?: string
  idToken?: string
  /** Unix seconds. */
  expiresAt: number
  subject: string
  tenantId: string
  display: string
  roles: string[]
  /** Unix seconds of the last authentication, used for step-up decisions. */
  authTime: number
  amr: string[]
}

/** Flow state carried between the authorize redirect and the callback. */
export interface AuthFlow {
  state: string
  nonce: string
  codeVerifier: string
  returnTo: string
}

function secret(): Buffer {
  const raw = process.env.SPECFORGE_SESSION_SECRET
  if (!raw || raw.length < 32) {
    // Failing loudly at startup is the point. A session key that silently falls
    // back to a default is a session key that is identical across every
    // deployment, which is indistinguishable from having no encryption at all.
    throw new Error(
      'SPECFORGE_SESSION_SECRET must be set to at least 32 characters. ' +
        'It is read from the environment and never from source.',
    )
  }
  return Buffer.from(hkdfSync('sha256', Buffer.from(raw, 'utf8'), Buffer.alloc(0), 'specforge.session.v1', 32))
}

function seal(payload: unknown): string {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', secret(), iv)
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8')
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()
  return [VERSION, iv.toString('base64url'), ciphertext.toString('base64url'), tag.toString('base64url')].join('.')
}

function open<T>(value: string): T | null {
  const parts = value.split('.')
  if (parts.length !== 4) return null
  const [version, ivPart, dataPart, tagPart] = parts as [string, string, string, string]
  if (!timingSafeEqualString(version, VERSION)) return null

  try {
    const decipher = createDecipheriv('aes-256-gcm', secret(), Buffer.from(ivPart, 'base64url'))
    decipher.setAuthTag(Buffer.from(tagPart, 'base64url'))
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(dataPart, 'base64url')),
      decipher.final(),
    ])
    return JSON.parse(plaintext.toString('utf8')) as T
  } catch {
    // A failed tag check means the cookie was tampered with or the key rotated.
    // Either way the correct answer is "no session", not a partial one.
    return null
  }
}

function timingSafeEqualString(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  if (ab.length !== bb.length) return false
  return timingSafeEqual(ab, bb)
}

/**
 * Decides whether the session cookie carries the Secure attribute.
 *
 * The answer comes from the URL the console is actually served on, not from
 * NODE_ENV. A production build served over plain http for local development is
 * a normal thing to do — `next start` behind `make dev` does exactly that — and
 * marking the cookie Secure there means the browser silently discards it and
 * every sign-in appears to fail for no visible reason.
 *
 * The default is Secure. Only an explicitly loopback http origin opts out, so a
 * misconfigured public URL fails closed rather than shipping session cookies in
 * clear text.
 */
function secureCookies(): boolean {
  const raw = process.env.SPECFORGE_PUBLIC_URL
  if (!raw) return process.env.NODE_ENV === 'production'
  try {
    const url = new URL(raw)
    if (url.protocol === 'https:') return true
    return !['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname)
  } catch {
    return true
  }
}

const baseCookie = {
  httpOnly: true,
  sameSite: 'lax' as const,
  path: '/',
  secure: secureCookies(),
}

export async function saveSession(session: Session): Promise<void> {
  const jar = await cookies()
  jar.set(COOKIE_NAME, seal(session), {
    ...baseCookie,
    // The cookie must not outlive the credential it carries.
    maxAge: Math.max(60, session.expiresAt - Math.floor(Date.now() / 1000)),
  })
}

export async function readSession(): Promise<Session | null> {
  const jar = await cookies()
  const raw = jar.get(COOKIE_NAME)?.value
  if (!raw) return null

  const session = open<Session>(raw)
  if (!session) return null
  if (session.expiresAt <= Math.floor(Date.now() / 1000)) return null
  return session
}

export async function clearSession(): Promise<void> {
  const jar = await cookies()
  jar.delete(COOKIE_NAME)
  jar.delete(FLOW_COOKIE)
}

export async function saveFlow(flow: AuthFlow): Promise<void> {
  const jar = await cookies()
  jar.set(FLOW_COOKIE, seal(flow), { ...baseCookie, maxAge: 600 })
}

export async function takeFlow(): Promise<AuthFlow | null> {
  const jar = await cookies()
  const raw = jar.get(FLOW_COOKIE)?.value
  if (!raw) return null
  // Single use: the verifier is consumed whether or not the callback succeeds,
  // so a replayed callback cannot reuse it.
  jar.delete(FLOW_COOKIE)
  return open<AuthFlow>(raw)
}

/**
 * Reports whether the session's authentication is recent enough to approve.
 *
 * The server enforces this too, and its answer is the one that counts. The
 * client-side check exists so the interface can ask for re-authentication
 * before someone types an approval comment, rather than after.
 */
export function stepUpFresh(session: Session, maxAgeSeconds = 900): boolean {
  const hasSecondFactor = session.amr.some((m) => ['mfa', 'otp', 'hwk', 'swk', 'pop'].includes(m))
  if (!hasSecondFactor) return false
  return Math.floor(Date.now() / 1000) - session.authTime <= maxAgeSeconds
}
