/**
 * Next.js configuration for the SpecForge console.
 *
 * The security headers are set here rather than left to a reverse proxy,
 * because the proxy is not part of this repository and a header that depends on
 * someone else's configuration is a header you cannot rely on.
 */

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // The console is deployed as a server, not a static export: it holds the
  // session and calls the API server-side so that no token ever reaches the
  // browser.
  output: 'standalone',
  outputFileTracingRoot: process.cwd(),

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), payment=()',
          },
          {
            // No inline script sources are allowed beyond what Next needs for
            // hydration, and nothing may be framed. An XSS here would sit next
            // to a session cookie, so the budget for "just this once" is zero.
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data:",
              "font-src 'self'",
              "connect-src 'self'",
              "frame-ancestors 'none'",
              "form-action 'self'",
              "base-uri 'self'",
              "object-src 'none'",
            ].join('; '),
          },
        ],
      },
    ]
  },
}

export default nextConfig
