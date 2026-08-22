import Link from 'next/link'

import { GovernedAction } from '@/components/governed-action'
import { Shell } from '@/components/shell'
import { Card, Cell, EmptyState, ErrorNote, Hash, Row, StatusBadge, Table, Time } from '@/components/ui'
import { approveVersion, requestChanges, reviseArtifact, submitForReview } from '../../actions'
import { api, attempt } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import { stepUpFresh } from '@/lib/session'
import type { ArtifactVersion, TracePath } from '@/lib/types'

export const dynamic = 'force-dynamic'

/**
 * One artifact, its version history and whatever action is legitimately
 * available on the current version.
 *
 * The page shows one action at a time — the one the current state permits —
 * rather than a row of buttons that mostly return errors. It also states, in
 * words, why a sealed version cannot be edited, because that is the single
 * property of the platform people most often try to work around.
 */
export default async function ArtifactPage({
  params,
}: {
  params: Promise<{ projectId: string; artifactId: string }>
}) {
  const { projectId, artifactId: rawArtifactId } = await params
  const artifactId = decodeURIComponent(rawArtifactId)
  const session = await requireSession(`/projects/${projectId}/artifacts/${rawArtifactId}`)
  const tenantId = session.tenantId

  const [tenantRes, projectsRes, artifactRes, upstreamRes, downstreamRes] = await Promise.all([
    attempt(() => api.tenant(tenantId)),
    attempt(() => api.projects(tenantId)),
    attempt(() => api.artifact(tenantId, projectId, artifactId)),
    attempt(() => api.upstream(tenantId, projectId, artifactId)),
    attempt(() => api.downstream(tenantId, projectId, artifactId)),
  ])

  const tenant = 'data' in tenantRes ? tenantRes.data : undefined
  const projects = 'data' in projectsRes ? projectsRes.data.items : []

  if ('error' in artifactRes) {
    return (
      <Shell session={session} tenant={tenant} projects={projects} current="/projects">
        <ErrorNote
          title="This artifact could not be read"
          detail={artifactRes.error.detail}
          traceId={artifactRes.error.traceId}
        />
      </Shell>
    )
  }

  const { artifact, versions } = artifactRes.data
  const sorted = [...versions].sort((a, b) => b.version - a.version)
  const head = sorted.find((v) => v.version === artifact.current_version) ?? sorted[0]
  const canStepUp = stepUpFresh(session)

  const upstream = 'data' in upstreamRes ? (upstreamRes.data.paths ?? []) : []
  const downstream = 'data' in downstreamRes ? (downstreamRes.data.paths ?? []) : []

  return (
    <Shell session={session} tenant={tenant} projects={projects} current="/projects">
      <nav className="mb-4 flex items-center gap-1.5 text-xs text-[--color-ink-faint]">
        <Link href="/projects" className="hover:text-[--color-ink]">
          Projects
        </Link>
        <span>/</span>
        <Link href={`/projects/${projectId}`} className="hover:text-[--color-ink]">
          {projects.find((p) => p.project_id === projectId)?.key ?? 'project'}
        </Link>
        <span>/</span>
        <span className="font-mono text-[--color-ink-muted]">{artifact.artifact_id}</span>
      </nav>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold tracking-tight">{artifact.title}</h1>
          <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs text-[--color-ink-muted]">
            <span className="font-mono">{artifact.artifact_id}</span>
            <span>·</span>
            <span>{artifact.artifact_type}</span>
            <span>·</span>
            <span>version {artifact.current_version}</span>
          </div>
        </div>
        <StatusBadge status={artifact.status} />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {head && <VersionContent version={head} />}

          <Card title="Version history" description="Approved versions are never edited; revisions create new ones.">
            <Table head={['Version', 'Status', 'Content hash', 'Approved by', 'When']}>
              {sorted.map((v) => (
                <Row key={v.version}>
                  <Cell className="font-mono text-xs">{v.version}</Cell>
                  <Cell>
                    <StatusBadge status={v.status} />
                  </Cell>
                  <Cell>
                    <Hash value={v.content_hash} />
                  </Cell>
                  <Cell className="font-mono text-[11px] text-[--color-ink-muted]">
                    {v.approved_by ? `${v.approved_by.slice(0, 8)}…` : '—'}
                  </Cell>
                  <Cell>
                    <Time value={v.approved_at ?? v.updated_at} />
                  </Cell>
                </Row>
              ))}
            </Table>
          </Card>

          <div className="grid gap-6 md:grid-cols-2">
            <TraceCard
              title="Upstream"
              description="Why does this exist?"
              empty="Nothing in the graph derives this artifact yet."
              paths={upstream}
              truncated={'data' in upstreamRes ? upstreamRes.data.truncated : false}
            />

            <TraceCard
              title="Downstream"
              description="What implements this?"
              empty="Nothing implements this artifact yet."
              paths={downstream}
              truncated={'data' in downstreamRes ? downstreamRes.data.truncated : false}
            />
          </div>
        </div>

        <div className="space-y-6">
          {head && (
            <Card title="Action" description={actionDescription(head)}>
              <ArtifactActions
                projectId={projectId}
                artifactId={artifact.artifact_id}
                version={head}
                canStepUp={canStepUp}
              />
            </Card>
          )}

          {head?.approval_evidence && (
            <Card title="Approval evidence" description="Written once, before the row was sealed.">
              <dl className="space-y-2.5 text-xs">
                <Field label="Evidence" value={head.approval_evidence.evidence_id} mono />
                <Field label="Digest" value={head.approval_evidence.digest} mono wrap />
                <Field label="Approver" value={head.approved_by ?? '—'} mono />
                <Field label="Comment" value={head.approval_comment ?? '—'} wrap />
                {head.approval_evidence.gate_decisions && head.approval_evidence.gate_decisions.length > 0 && (
                  <div>
                    <dt className="text-[--color-ink-faint]">Gates</dt>
                    <dd className="mt-1 space-y-1">
                      {head.approval_evidence.gate_decisions.map((g, i) => (
                        <p key={i} className="font-mono text-[11px] text-[--color-ink-muted]">
                          {g.gate}: {g.decision}
                        </p>
                      ))}
                    </dd>
                  </div>
                )}
              </dl>
              <p className="mt-3 border-t border-[--color-border-subtle] pt-3 text-[11px] leading-relaxed text-[--color-ink-faint]">
                Verify offline, without trusting this console:
                <code className="mt-1 block font-mono text-[10px] text-[--color-ink-muted]">
                  specforge-cli verify-evidence --file evidence.json --digest {head.approval_evidence.digest.slice(0, 20)}…
                </code>
              </p>
            </Card>
          )}

          {head?.generator && head.generator.kind !== 'USER' && (
            <Card title="Provenance" description="This content was not written by a person.">
              <dl className="space-y-2 text-xs">
                <Field label="Origin" value={head.generator.kind} />
                {head.generator.model && <Field label="Model" value={head.generator.model} mono />}
                {head.generator.provider && <Field label="Provider" value={head.generator.provider} />}
                {head.generator.prompt_version && (
                  <Field label="Prompt" value={head.generator.prompt_version} mono />
                )}
                {head.generator.guardrail_chain_version && (
                  <Field label="Guardrails" value={head.generator.guardrail_chain_version} mono />
                )}
              </dl>
              <p className="mt-3 text-[11px] leading-relaxed text-[--color-ink-faint]">
                Generated content carries the prompt, model and guardrail versions that produced it, so
                the generation can be reproduced and reviewed rather than taken on trust.
              </p>
            </Card>
          )}
        </div>
      </div>
    </Shell>
  )
}

/**
 * One direction of the traversal.
 *
 * A path is rendered as the chain of hops that produced it, not just its
 * endpoint, because "this specification traces to that requirement" is only
 * meaningful if you can see which links carried the claim — and whether any of
 * them was proposed by a model rather than asserted by a person.
 */
function TraceCard({
  title,
  description,
  empty,
  paths,
  truncated,
}: {
  title: string
  description: string
  empty: string
  paths: TracePath[]
  truncated: boolean
}) {
  return (
    <Card title={title} description={description}>
      {paths.length === 0 ? (
        <EmptyState title="No paths" hint={empty} />
      ) : (
        <ul className="space-y-3">
          {paths.slice(0, 8).map((path) => (
            <li key={`${path.target.artifact_id}:${path.target.version}`}>
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-mono text-[11px] font-medium text-[--color-ink]">
                  {path.target.artifact_id}
                </span>
                <span className="text-[10px] text-[--color-ink-faint]">
                  {path.artifact_type} · depth {path.depth}
                </span>
              </div>
              {path.title && <p className="truncate text-[11px] text-[--color-ink-muted]">{path.title}</p>}
              <p className="mt-0.5 font-mono text-[10px] leading-relaxed text-[--color-ink-faint]">
                {path.hops
                  .map((h) => `${h.from.artifact_id} —${h.link_type}${h.origin === 'LLM_PROPOSED' ? '◆' : ''}→ ${h.to.artifact_id}`)
                  .join(' · ')}
              </p>
            </li>
          ))}
        </ul>
      )}
      {truncated && (
        <p className="mt-3 rounded bg-[--color-review-soft] px-2 py-1.5 text-[10px] text-[--color-review]">
          The walk hit the configured depth limit, so this answer is partial.
        </p>
      )}
    </Card>
  )
}

function actionDescription(v: ArtifactVersion): string {
  switch (v.status) {
    case 'DRAFT':
      return 'This draft can be edited and submitted for review.'
    case 'CHANGES_REQUESTED':
      return 'A reviewer asked for changes. Resubmit when they are made.'
    case 'USER_REVIEW':
      return 'Awaiting a reviewer who did not author any version of this artifact.'
    case 'AI_REVIEW':
      return 'Automated review is running. Its findings are advisory; a person still decides.'
    case 'APPROVED':
      return 'Sealed. The bytes cannot change; a revision creates a new version.'
    case 'FROZEN':
      return 'Frozen as a release baseline.'
    case 'SUPERSEDED':
      return 'A later version has been approved.'
    default:
      return 'No action is available in this state.'
  }
}

function ArtifactActions({
  projectId,
  artifactId,
  version,
  canStepUp,
}: {
  projectId: string
  artifactId: string
  version: ArtifactVersion
  canStepUp: boolean
}) {
  const v = version.version

  if (version.status === 'DRAFT' || version.status === 'CHANGES_REQUESTED') {
    return (
      <GovernedAction
        label="Submit for review"
        prompt="Note for the reviewer (optional)"
        placeholder="What changed and what should be checked."
        run={submitForReview.bind(null, projectId, artifactId, v)}
      />
    )
  }

  if (version.status === 'USER_REVIEW') {
    return (
      <div className="space-y-6">
        {!canStepUp && (
          <div className="rounded-lg bg-[--color-review-soft] px-3 py-2 text-[11px] leading-relaxed text-[--color-review]">
            Your sign-in does not currently carry a recent second factor. Approval will be refused until
            you re-authenticate — better to do it before writing the comment than after.
          </div>
        )}
        <GovernedAction
          label="Approve and seal"
          prompt="Approval comment (required)"
          placeholder="State what you verified: the acceptance criteria, the upstream requirement, the security rules."
          confirm="Approving writes evidence to write-once storage and makes this version immutable. It cannot be edited afterwards; a change requires a new version."
          run={approveVersion.bind(null, projectId, artifactId, v)}
        />
        <div className="border-t border-[--color-border-subtle] pt-5">
          <GovernedAction
            label="Request changes"
            prompt="What needs to change (required)"
            placeholder="Be specific: the author only sees this comment."
            tone="neutral"
            run={requestChanges.bind(null, projectId, artifactId, v)}
          />
        </div>
      </div>
    )
  }

  if (version.status === 'APPROVED' || version.status === 'FROZEN') {
    return (
      <div className="space-y-4">
        <p className="rounded-lg bg-[--color-sealed-soft] px-3 py-2 text-[11px] leading-relaxed text-[--color-sealed]">
          This version is sealed. The database refuses updates to it and no API path can modify it. That
          is what makes the approval evidence meaningful.
        </p>
        <GovernedAction
          label="Open a revision"
          prompt="Why is this being revised? (required)"
          placeholder="The reason this approved artifact needs to change."
          tone="neutral"
          confirm="A new draft is created from this content. The approved version stays readable and authoritative until the new one is approved."
          run={reviseArtifact.bind(null, projectId, artifactId)}
        />
      </div>
    )
  }

  return (
    <p className="text-xs text-[--color-ink-muted]">
      No action is available while this version is {version.status.toLowerCase().replace('_', ' ')}.
    </p>
  )
}

function VersionContent({ version }: { version: ArtifactVersion }) {
  return (
    <Card
      title={`Version ${version.version}`}
      description={version.change_summary || undefined}
      action={<Hash value={version.content_hash} />}
    >
      <pre className="max-h-[28rem] overflow-auto rounded-lg bg-[--color-surface-sunken] p-4 text-xs leading-relaxed">
        <code>{JSON.stringify(version.content, null, 2)}</code>
      </pre>
      <p className="mt-3 text-[11px] leading-relaxed text-[--color-ink-faint]">
        The hash covers the canonical (RFC 8785) form of this content and the version&rsquo;s identity,
        but not its status or approval fields — so the hash of an approved version is the hash of exactly
        the bytes that were reviewed, and it does not change as the version moves through its lifecycle.
      </p>
    </Card>
  )
}

function Field({ label, value, mono, wrap }: { label: string; value: string; mono?: boolean; wrap?: boolean }) {
  return (
    <div>
      <dt className="text-[--color-ink-faint]">{label}</dt>
      <dd
        className={`mt-0.5 text-[--color-ink-muted] ${mono ? 'font-mono text-[11px]' : ''} ${
          wrap ? 'break-all' : 'truncate'
        }`}
      >
        {value}
      </dd>
    </div>
  )
}
