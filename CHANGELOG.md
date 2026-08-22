# Changelog

All notable changes to SpecForge are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For this product, a **breaking change** includes anything that alters what a
previously approved artifact hashes to, changes the meaning of a recorded
audit action, or removes a guarantee the API documents — not only an
incompatible request or response shape.

## [Unreleased]

## [1.0.0] — 2026-08-22

The first release. Phase 1 of the implementation plan is complete and verified:
repository, authentication, tenants, projects, the artifact graph, the audit
trail, and the console.

### Added

- **Canonical artifact model.** Content-addressed versions hashed as
  `SHA-256(JCS(envelope))` using RFC 8785 canonical JSON, so the hash is
  reproducible in any language. The envelope excludes `status`, the approval
  fields and trace links, which gives the property that matters: the hash of an
  approved version is the hash of exactly the bytes that were reviewed.
- **Immutability enforced twice.** Sealing in the domain, and a database trigger
  that refuses to modify a sealed row independently of the application.
- **Tenant isolation in PostgreSQL.** Row-level security with
  `FORCE ROW LEVEL SECURITY`, keyed on a session variable set per transaction. A
  missing tenant context returns no rows rather than everything.
- **Hash-chained audit trail.** Per-tenant gapless sequences, append-only by
  trigger and by grant, with chain anchors published to write-once storage so a
  rewrite of history cannot also rewrite its own external reference.
- **Governed approval path.** Gates, four-eyes, step-up freshness, evidence
  written to write-once storage *before* the row is sealed, and the state
  change, audit record and domain event committed in a single transaction.
- **Traceability.** Typed links with provenance; upstream, downstream and
  deterministic impact queries. A model-proposed link cannot reach `ACCEPTED`
  without a recorded human disposition — enforced by a database constraint.
- **Authentication.** OIDC authorization-code flow with PKCE (S256),
  asymmetric-only token verification, and a development identity provider that
  refuses to run in production.
- **Console.** A server-rendered Next.js application that holds the access token
  on the server and gives the browser only an encrypted session cookie.
- **AI platform ports** with a deterministic offline simulator covering all
  eight prompt purposes. Generated content carries the prompt, model and
  guardrail chain versions that produced it.
- **Operations.** Docker images, a Helm chart whose preconditions refuse to
  render a configuration that disables object lock or four-eyes in production,
  Terraform for VPC, Aurora, S3 with Object Lock and EKS, and CI that asserts
  the database invariants on every pull request.
- **Verification tooling.** `specforge-cli verify-audit` recomputes the chain
  against a published anchor; `verify-evidence` checks an exported approval
  offline without contacting the platform.

### Security

- API keys cannot hold approval permissions — refused by the application *and*
  by a database `CHECK` constraint.
- Service accounts cannot approve anything, whatever their token claims.
- Every route declares a permission; the server refuses to start otherwise, and
  the public surface is pinned by a test.
- No third-party Go dependencies. Every line handling a tenant's data is in this
  repository and reviewable.

[Unreleased]: https://github.com/udaykishoreresu/specforge/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/udaykishoreresu/specforge/releases/tag/v1.0.0
