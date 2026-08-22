# Testing the local stack

`make dev` prints six URLs. This is how to check each of them, and — more
usefully — how to check the things they exist to serve.

The short version:

```bash
make smoke
```

That runs every check below against the running stack and exits non-zero if any
of them fail. The rest of this page explains what it checks and how to do each
part by hand.

---

## Before anything else: the tenant claim

The development identity provider issues tokens scoped to the tenant the seeder
created, and it reads that tenant from `SF_DEV_TENANT_ID` **at startup**. If the
API process never saw it, every token is tenantless, the console shows *No
tenant context*, and every other check fails for a reason that nothing points
at.

`make dev` now wires this itself: it reads the id back from the database after
seeding, writes it to `deploy/docker/.env`, and restarts the API. Confirm it
took:

```bash
docker compose -f deploy/docker/docker-compose.yml exec api env | grep SF_DEV_TENANT_ID
```

If it is empty, exporting the variable in your own shell will not help — the
value has to reach the container:

```bash
echo "SF_DEV_TENANT_ID=$(make -s tenant-id)" > deploy/docker/.env
docker compose -f deploy/docker/docker-compose.yml up -d api
```

## Getting a token

Everything below the health checks needs one. `scripts/dev-token.sh` walks the
same authorization-code flow with PKCE that the console walks in a browser —
there is no shortcut endpoint, because a shortcut endpoint is something that
eventually ships.

```bash
TOKEN=$(scripts/dev-token.sh owner)      # or: make token ROLE=owner
curl -sS -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/v1/auth/me
```

Twelve accounts exist, one per role: `admin`, `owner`, `analyst`, `architect`,
`dev`, `qa`, `ops`, `sec`, `compliance`, `auditor`, `viewer`, `platform`.
Switching between them is how you exercise authorization.

---

## API — http://localhost:8080

```bash
curl -s localhost:8080/healthz                 # the process is alive
curl -s localhost:8080/readyz                  # database, cache and object store are reachable
curl -s localhost:8080/api/v1/version          # which commit is running
curl -s localhost:8080/api/v1/openapi.json | head -c 400
curl -s localhost:8080/metrics | grep '^sf_'   # the platform's own metrics
```

`/readyz` is the interesting one: it fails when a dependency is down, which is
what makes it safe to put in front of a load balancer.

Then check that the API refuses what it should:

```bash
# No token: 401.
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/api/v1/auth/me

# A token signed with "none": still 401. The verifier is asymmetric-only, so
# algorithm confusion does not get you in.
FORGED="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.$(cut -d. -f2 <<<"$TOKEN")."
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $FORGED" \
  localhost:8080/api/v1/auth/me
```

## Development identity provider — http://localhost:8081

```bash
curl -s localhost:8081/.well-known/openid-configuration | head -c 400
curl -s localhost:8081/jwks.json          # RSA public key, no shared secret anywhere
curl -s localhost:8081/users              # the twelve seeded accounts
```

Two things worth confirming, because they are the properties that make this a
real OIDC provider rather than a token dispenser:

- `code_challenge_methods_supported` contains `S256` and only `S256`.
- An authorization code is single use. Run the exchange in `dev-token.sh` twice
  with the same code and the second attempt returns `invalid_grant`.

## Console — http://localhost:3000

Open it in a browser. The path worth walking:

1. **Sign in as Analyst.** You land on the demo project (`acme` / `PAY`).
2. **Open `REQ-PAY-001`.** It is `APPROVED`. There is no edit affordance — an
   approved version is sealed, and the UI does not offer what the API would
   refuse.
3. **Revise it.** That creates version 2 as a `DRAFT`. Edit and submit it.
4. **Try to approve your own submission.** The button is not there, and if you
   call the endpoint directly you get a 403. Four-eyes: the author cannot
   approve.
5. **Sign out, sign in as Owner, approve it.** Note the step-up prompt — the
   approval permission requires MFA, and the Owner account satisfies it.
6. **Open the evidence.** Copy the digest. Verify it offline, without the
   platform vouching for itself:

   ```bash
   specforge-cli verify-evidence --file evidence.json --digest sha256:...
   ```

7. **Sign in as Auditor.** The audit trail shows every step, hash-chained. The
   Verify button recomputes it.
8. **Sign in as Viewer.** Everything is read-only. This is the check that the
   permission bitset is actually consulted rather than the UI merely hiding
   buttons.

Header checks, from the shell:

```bash
curl -sI localhost:3000/ | grep -i 'content-security-policy'
curl -sI localhost:3000/api/auth/login | grep -i '^location'   # /authorize?...code_challenge=...
```

The browser never receives a token. The session is a server-held encrypted
cookie and the Next.js server calls the API on your behalf, so an XSS on the
page has nothing to steal.

## Traceability and governance, by API

```bash
TENANT=$(make -s tenant-id)
PROJECT=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "localhost:8080/api/v1/tenants/$TENANT/projects" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
BASE="localhost:8080/api/v1/tenants/$TENANT/projects/$PROJECT"

curl -s -H "Authorization: Bearer $TOKEN" "$BASE/artifacts"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/trace/upstream?artifact_id=SPEC-PAY-001"
curl -s -H "Authorization: Bearer $TOKEN" "$BASE/trace/impact?artifact_id=REQ-PAY-001"
```

Then the two refusals that matter:

```bash
VIEWER=$(scripts/dev-token.sh viewer)

# A viewer cannot approve — 403, not 401: authenticated, not permitted.
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  -H "Authorization: Bearer $VIEWER" -H 'Content-Type: application/json' \
  -d '{"comment":"nope"}' "$BASE/artifacts/REQ-PAY-001/versions/1/approve"

# An approved version cannot be edited, by anyone, at any level.
curl -s -o /dev/null -w '%{http_code}\n' -X PUT \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"rewritten"}' "$BASE/artifacts/REQ-PAY-001/versions/1"
```

## Audit — the chain

Through the API:

```bash
AUDITOR=$(scripts/dev-token.sh auditor)
curl -s -X POST -H "Authorization: Bearer $AUDITOR" -H 'Content-Type: application/json' \
  -d '{}' "localhost:8080/api/v1/tenants/$TENANT/audit/verify"
```

And independently, recomputed from stored bytes rather than by asking the
platform to confirm its own record:

```bash
make verify-audit TENANT=$TENANT
```

The second one is the check that means something. It compares the recomputed
chain against the last published anchor, so a rewrite that also rewrote every
hash still fails.

To see it catch tampering, alter a stored record by hand and re-run it — the
report names the first sequence that diverges. The database refuses `UPDATE` and
`DELETE` on audit rows, so you will need to be the table owner to try.

## Grafana — http://localhost:3001

Anonymous viewing is on, so it opens straight to the dashboards; sign in as
`admin` / `admin` to edit. The dashboard is **SpecForge — Governance & Integrity**.

Worth watching while you walk the console journey above:

- `sf_artifact_versions_created_total` and `sf_approvals_total` — move as you
  revise and approve.
- `sf_audit_chain_valid` — must be `1`. Anything else is an incident.
- `sf_content_hash_mismatch_total` — must stay at zero. A non-zero value means
  stored bytes stopped matching their recorded digest.
- `sf_outbox_age_seconds` — the age of the oldest unpublished event. It should
  stay near zero; a rising value means the worker is not draining the outbox.
- `sf_security_events_total` — increments on each refusal, so the 401s and 403s
  you produce above should show up here.

Prometheus itself is at http://localhost:9091; check http://localhost:9091/targets
if a panel is empty, and http://localhost:9091/alerts for the rules.

## Jaeger — http://localhost:16686

Make a few requests first, then select service `specforge-api` and search. Open
an approval trace: one span per layer, and the database spans carry the tenant
id, which is how you confirm `SET LOCAL app.tenant_id` was applied on the
connection that ran the query.

If the service list is empty, the collector has not received anything —
`docker compose logs otel-collector`.

## MinIO — http://localhost:9001

Sign in with `specforge` / `specforge-dev-secret`. Three buckets:

| Bucket        | Holds                     | Object Lock |
| ------------- | ------------------------- | ----------- |
| `sf-content`  | artifact content, by hash | no          |
| `sf-evidence` | approval evidence         | yes         |
| `sf-audit`    | audit anchors             | yes         |

The lock is the point. Try deleting an object from `sf-evidence` in the console:
it is refused while the retention period holds, and it is refused for the root
credentials too. That is what makes the evidence survive an attacker who reaches
the keys.

```bash
docker compose -f deploy/docker/docker-compose.yml run --rm --entrypoint sh minio-init -c \
  'mc alias set l http://minio:9000 specforge specforge-dev-secret >/dev/null &&
   mc retention info --default l/sf-evidence'
```

---

## The tests that do not need a running stack

```bash
make check              # formatting, vet, route lint, dependency lint, unit and contract tests
make test-integration   # against a real PostgreSQL
make test-isolation     # the database invariants: RLS, immutability, audit chain
make verify-release     # all of the above, plus the version checks
```

`make test-isolation` is the one to run if you change a migration. It asserts,
directly against the database, that one tenant cannot read another's rows, that
sealed artifact versions cannot be deleted, and that the audit table refuses
mutation — without going through the application, which is the layer those
guarantees are meant to survive.
