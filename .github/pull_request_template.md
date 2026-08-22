## What this changes

<!-- One paragraph. What is different after this merges, and why. -->

## How you know it works

<!--
Not "tests pass" — what specifically demonstrates the change is correct?
A new test that fails on the previous commit, a manual reproduction, a query
against a seeded database. Say what you actually ran.
-->

## Governance checklist

Tick what applies; delete what does not. An unticked box is fine if the answer
is "not applicable" — an unticked box that should be ticked is not.

- [ ] `make check` passes locally
- [ ] `make test-isolation` passes (required for any change under `migrations/`)
- [ ] `make test-integration` passes (required for changes to the approval path)
- [ ] New endpoints declare a permission, and `api/openapi/specforge.v1.yaml` was updated
- [ ] New tenant-scoped tables have RLS, a `tenant_isolation` policy, and an assertion in `test/isolation/invariants.sql`
- [ ] No new path can modify a sealed artifact version
- [ ] No secret, key or credential appears in the diff
- [ ] Documentation under `docs/` reflects the change, if it changed a documented behaviour

## Risk

<!--
What could this break that the tests would not catch? If the answer is
genuinely "nothing", say so — but consider the audit trail, tenant isolation,
and anything that reads data written before this change.
-->

## Rollback

<!--
How is this undone? If it includes a migration, say whether reverting the
deployment alone is sufficient, and what the schema does in the meantime.
-->
