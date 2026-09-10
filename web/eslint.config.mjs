import nextCoreWebVitals from 'eslint-config-next/core-web-vitals'
import nextTypescript from 'eslint-config-next/typescript'

const config = [
  ...nextCoreWebVitals,
  ...nextTypescript,
  {
    ignores: ['.next/**', 'out/**', 'next-env.d.ts'],
  },
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
    },
  },
  {
    // Client components live under src/components. Route handlers, server
    // components and server actions under src/app are allowed to touch the
    // session; a client bundle never is.
    files: ['src/components/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['**/lib/session*'],
              importNames: ['sealSession', 'readSession'],
              message:
                'Session handling is server-only. Import it from a route handler or a server component, never from a client component.',
            },
          ],
        },
      ],
    },
  },
]

export default config
