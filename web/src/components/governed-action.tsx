'use client'

import { useState, useTransition } from 'react'

import type { ActionResult } from '@/app/projects/[projectId]/actions'

/**
 * A governed action: a comment, a button, and an honest report of what the
 * platform said.
 *
 * The comment box is not optional decoration. For an approval it becomes part
 * of the write-once evidence document, so the interface treats it as the
 * primary input and the button as secondary. Refusals are shown in place, with
 * the remedy attached — a four-eyes refusal explains that someone else must
 * review; a step-up refusal offers the re-authentication link.
 */
export function GovernedAction({
  label,
  prompt,
  placeholder,
  tone = 'primary',
  confirm,
  run,
}: {
  label: string
  prompt: string
  placeholder: string
  tone?: 'primary' | 'neutral' | 'danger'
  /** Extra sentence shown above the button for consequential actions. */
  confirm?: string
  run: (comment: string) => Promise<ActionResult>
}) {
  const [comment, setComment] = useState('')
  const [result, setResult] = useState<ActionResult | null>(null)
  const [pending, startTransition] = useTransition()

  const toneClass =
    tone === 'primary'
      ? 'bg-[--color-accent] text-white hover:opacity-90'
      : tone === 'danger'
        ? 'bg-[--color-danger] text-white hover:opacity-90'
        : 'border border-[--color-border-strong] text-[--color-ink] hover:bg-[--color-surface-raised]'

  return (
    <div className="space-y-2.5">
      <label className="block">
        <span className="text-xs font-medium text-[--color-ink-muted]">{prompt}</span>
        <textarea
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          rows={3}
          placeholder={placeholder}
          disabled={pending}
          className="mt-1.5 w-full resize-y rounded-lg border border-[--color-border-subtle] bg-[--color-surface] px-3 py-2 text-sm placeholder:text-[--color-ink-faint] disabled:opacity-60"
        />
      </label>

      {confirm && <p className="text-[11px] leading-relaxed text-[--color-ink-faint]">{confirm}</p>}

      <button
        type="button"
        disabled={pending}
        onClick={() =>
          startTransition(async () => {
            const r = await run(comment)
            setResult(r)
            if (r.ok) setComment('')
          })
        }
        className={`rounded-lg px-3.5 py-2 text-sm font-medium transition-opacity disabled:opacity-50 ${toneClass}`}
      >
        {pending ? 'Working…' : label}
      </button>

      {result && (
        <div
          role="status"
          className={`rounded-lg px-3 py-2 text-xs ${
            result.ok
              ? 'bg-[--color-sealed-soft] text-[--color-sealed]'
              : 'bg-[--color-danger-soft] text-[--color-danger]'
          }`}
        >
          <p>{result.message}</p>
          {result.code && !result.ok && (
            <p className="mt-1 font-mono text-[10px] opacity-70">{result.code}</p>
          )}
          {result.stepUpUrl && (
            // A real navigation, for the same reason as the sign-in link: this
            // route redirects to the identity provider.
            <a href={result.stepUpUrl} className="mt-1.5 inline-block font-medium underline">
              Re-authenticate with a second factor
            </a>
          )}
        </div>
      )}
    </div>
  )
}
