'use server'

import { revalidatePath } from 'next/cache'

import { ApiError, api } from '@/lib/api'
import { requireSession } from '@/lib/guard'

/**
 * Server actions for the governed transitions.
 *
 * These run on the server, with the session's token, and they do not decide
 * anything: the platform API evaluates gates, four-eyes and step-up, and its
 * refusal is returned to the interface as-is. The console's job is to present
 * that refusal in a way that tells the reviewer what to do next.
 */

export interface ActionResult {
  ok: boolean
  message?: string
  code?: string
  /** Set when re-authentication with a second factor would unblock the action. */
  stepUpUrl?: string
}

function fail(err: unknown, returnTo: string): ActionResult {
  if (err instanceof ApiError) {
    if (err.needsStepUp) {
      return {
        ok: false,
        code: err.code,
        message: 'Approving requires a recent second authentication factor.',
        stepUpUrl: `/api/auth/stepup?returnTo=${encodeURIComponent(returnTo)}`,
      }
    }
    if (err.isFourEyes) {
      return {
        ok: false,
        code: err.code,
        message:
          'You authored a version of this artifact, so you cannot approve it. Someone who did not write it must review.',
      }
    }
    return { ok: false, code: err.code, message: err.detail }
  }
  return { ok: false, message: err instanceof Error ? err.message : 'The action failed.' }
}

export async function submitForReview(
  projectId: string,
  artifactId: string,
  version: number,
  comment: string,
): Promise<ActionResult> {
  const session = await requireSession()
  const path = `/projects/${projectId}/artifacts/${artifactId}`
  try {
    await api.submit(session.tenantId, projectId, artifactId, version, comment)
    revalidatePath(path)
    return { ok: true, message: 'Submitted for review.' }
  } catch (err) {
    return fail(err, path)
  }
}

export async function requestChanges(
  projectId: string,
  artifactId: string,
  version: number,
  comment: string,
): Promise<ActionResult> {
  const session = await requireSession()
  const path = `/projects/${projectId}/artifacts/${artifactId}`
  if (!comment.trim()) {
    return { ok: false, message: 'Say what needs to change; the author only sees this comment.' }
  }
  try {
    await api.requestChanges(session.tenantId, projectId, artifactId, version, comment)
    revalidatePath(path)
    return { ok: true, message: 'Returned to the author.' }
  } catch (err) {
    return fail(err, path)
  }
}

export async function approveVersion(
  projectId: string,
  artifactId: string,
  version: number,
  comment: string,
): Promise<ActionResult> {
  const session = await requireSession()
  const path = `/projects/${projectId}/artifacts/${artifactId}`

  if (!comment.trim()) {
    // The API enforces this too. Catching it here keeps the reviewer's typed
    // text on screen instead of round-tripping to a 400.
    return { ok: false, message: 'An approval comment is required. It becomes part of the evidence record.' }
  }

  // The idempotency key is derived from what is being approved, so a
  // double-submitted form replays the original approval rather than creating a
  // second one.
  const key = `approve:${projectId}:${artifactId}:${version}:${session.subject}`

  try {
    const sealed = await api.approve(session.tenantId, projectId, artifactId, version, comment, key)
    revalidatePath(path)
    return {
      ok: true,
      message: `Approved and sealed. Evidence ${sealed.approval_evidence?.evidence_id ?? 'recorded'}.`,
    }
  } catch (err) {
    return fail(err, path)
  }
}

export async function reviseArtifact(
  projectId: string,
  artifactId: string,
  changeSummary: string,
): Promise<ActionResult> {
  const session = await requireSession()
  const path = `/projects/${projectId}/artifacts/${artifactId}`

  if (!changeSummary.trim()) {
    return { ok: false, message: 'A change summary is required: it explains why the approved version is being reopened.' }
  }

  const key = `revise:${projectId}:${artifactId}:${changeSummary.slice(0, 64)}`
  try {
    const draft = await api.revise(session.tenantId, projectId, artifactId, changeSummary, key)
    revalidatePath(path)
    return { ok: true, message: `Draft version ${draft.version} opened. The approved version is untouched.` }
  } catch (err) {
    return fail(err, path)
  }
}

export async function decideLink(
  projectId: string,
  linkId: string,
  decision: 'accept' | 'reject',
  comment: string,
): Promise<ActionResult> {
  const session = await requireSession()
  const path = `/projects/${projectId}`

  if (!comment.trim()) {
    return {
      ok: false,
      message:
        'A disposition comment is required. For a model-proposed link it is the recorded human decision the database demands before the link may be accepted.',
    }
  }

  try {
    if (decision === 'accept') {
      await api.acceptLink(session.tenantId, projectId, linkId, comment)
    } else {
      await api.rejectLink(session.tenantId, projectId, linkId, comment)
    }
    revalidatePath(path)
    return { ok: true, message: decision === 'accept' ? 'Link accepted.' : 'Link rejected.' }
  } catch (err) {
    return fail(err, path)
  }
}
