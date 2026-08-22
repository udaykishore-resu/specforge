# Contributing to SpecForge

SpecForge is a governance platform, so the bar for changes to it is the same bar
it applies to the artifacts it governs: a change should be traceable to a
reason, reviewed by someone who did not write it, and verifiable by someone who
does not trust the author.

## Before you start

```bash
make dev          # the full local stack, migrated and seeded
make check        # everything CI runs on a pull request
```

If `make check` is red on a clean checkout, that is a bug in the repository, not
in your machine. Please open an issue.

## The checks, and why each exists

| Command                 | What it protects                                                        |
| ----------------------- | ----------------------------------------------------------------------- |
| `make fmt-check`        | One formatting, so diffs show intent rather than whitespace              |
| `make vet`              | The obvious mistakes the compiler permits                                |
| `make lint-routes`      | Every endpoint declares a permission; the public surface is the approved one |
| `make lint-deps`        | No third-party Go dependency arrives by accident                         |
| `make test`             | Unit and contract tests, including OpenAPI-against-router                |
| `make test-isolation`   | Tenancy, immutability and audit invariants, asserted in SQL              |
| `make test-integration` | The governed journey end to end against PostgreSQL                       |

`make test-isolation` is the one that matters most. It asserts, against a real
database, that a tenant cannot read another tenant's rows, that an approved
version cannot be modified or deleted, that an audit record cannot be updated
even by the table owner, and that an API key cannot hold an approval
permission. If a change makes one of those fail, the change is wrong — the
assertion is not.

## Rules that are not negotiable

These are properties the product sells. A pull request that weakens one will be
declined regardless of what it enables.

1. **Approved artifacts are immutable.** No new code path may modify a sealed
   version. Changes create new versions.
2. **No model output becomes authoritative.** AI proposes; deterministic
   validation, policy and a human approval decide. A trace link proposed by a
   model cannot reach `ACCEPTED` without a recorded human disposition.
3. **Every route declares a permission.** `Route()` requires one and the server
   refuses to start without it. Do not add an escape hatch.
4. **The audit trail is append-only.** No `UPDATE` or `DELETE` on
   `audit_records`, in code or in a migration.
5. **Authorization is enforced in more than one place.** Where the database can
   also enforce a rule — as it does for API keys and approval permissions — it
   should.
6. **No secret in source.** Not in a default, not in a test fixture, not in a
   compose file that "is only local". Configuration comes from the environment.

## Adding a dependency

The platform has no third-party Go dependencies, and `make lint-deps` fails the
build if one appears. That is a deliberate choice for a platform whose job is
provenance, not a superstition — but it is not a prohibition. If a dependency is
genuinely the right answer:

1. Open an issue explaining what it does that the standard library cannot.
2. Say who maintains it, how it is released, and what its own dependency tree
   looks like.
3. Update `make lint-deps` in the same pull request, so the exception is
   recorded rather than silently permitted.

## Database changes

Migrations are forward-only and numbered. Never edit a migration that has been
applied anywhere; add a new one.

A migration that adds a table holding tenant data must, in the same migration:

- enable `ROW LEVEL SECURITY` **and** `FORCE ROW LEVEL SECURITY`
- add a `tenant_isolation` policy keyed on `sf_current_tenant()`
- add an assertion to `test/isolation/invariants.sql` proving the isolation holds

The last point is the one people forget. A policy nobody tests is a policy that
stops working the first time someone refactors around it.

## API changes

The OpenAPI document in `api/openapi/specforge.v1.yaml` is checked against the
running router by `test/contract`. Adding an endpoint without documenting it —
or documenting one that does not exist — fails the build. Update both in the
same commit.

## Commits and pull requests

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(artifactgraph): add impact analysis depth limit
fix(audit): compare anchors before reporting a chain valid
docs(security): document the step-up freshness window
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`, `perf`,
`chore`, `revert`. A `!` after the scope, or a `BREAKING CHANGE:` footer, marks
an incompatible change.

Install the hooks once so the format is checked before the commit rather than in
review:

```bash
make hooks
```

In the pull request, say what the change does and how you know it works. "Tests
pass" is not how you know it works; "the new invariant fails on the previous
commit and passes on this one" is.

## Review

Every pull request needs an approving review from someone who did not write it.
This is the same four-eyes rule the platform enforces on artifacts, applied to
its own source. Changes touching `internal/platform/authz`,
`internal/platform/authn`, `internal/audit`, or `migrations/` additionally need
a review from a code owner (see `.github/CODEOWNERS`).

## Security

Do not open a public issue for a vulnerability. `SECURITY.md` explains how to
report one privately.
