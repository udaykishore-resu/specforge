import 'server-only'

import type { NextRequest } from 'next/server'

/**
 * Resolves the origin the browser is actually using.
 *
 * `request.nextUrl.origin` is derived from the address the server is bound to,
 * which in a container is `0.0.0.0` and behind a proxy is the internal service
 * name. Redirecting a browser there sends it to a different origin from the one
 * holding its session cookie, and the visible symptom is an endless bounce back
 * to the sign-in page.
 *
 * The configured public URL is therefore authoritative, and the request origin
 * is only a fallback for a development server started without one. Taking the
 * origin from configuration rather than from the request also means a forged
 * Host header cannot steer a post-authentication redirect.
 */
export function publicOrigin(request: NextRequest): string {
  const configured = process.env.SPECFORGE_PUBLIC_URL
  if (configured) {
    try {
      return new URL(configured).origin
    } catch {
      // A malformed value should not take the console down; fall through to the
      // request origin and let the misconfiguration be visible in the URL bar.
    }
  }
  return request.nextUrl.origin
}

/**
 * Builds an absolute URL on the public origin for a same-site path.
 *
 * Only paths are accepted. A caller that passes an absolute URL — say, one
 * echoed from a query parameter — gets the origin's root instead, which is what
 * turns an open-redirect attempt into a harmless bounce to the home page.
 */
export function publicUrl(request: NextRequest, path: string): URL {
  const safe = path.startsWith('/') && !path.startsWith('//') ? path : '/'
  return new URL(safe, publicOrigin(request))
}
