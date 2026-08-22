import { dirname } from 'path'
import { fileURLToPath } from 'url'
import { FlatCompat } from '@eslint/eslintrc'

const compat = new FlatCompat({ baseDirectory: dirname(fileURLToPath(import.meta.url)) })

export default [
  ...compat.extends('next/core-web-vitals', 'next/typescript'),
  {
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
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
