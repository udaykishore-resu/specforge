# Security Policy

## Reporting a vulnerability

Report privately. Do not open a public issue, and do not include a working
exploit in the first message.

- **GitHub Security Advisories** — the *Security* tab, *Report a vulnerability*.
  Preferred, because it keeps the report, the fix and the disclosure together.
- **Email** — `security@specforge.example.com`.

Please include what you can: the affected component and version, what an
attacker gains, and the smallest reproduction you have. If you are unsure
whether something is a vulnerability, report it anyway — a false positive costs
an hour, and a missed report costs considerably more.

### What to expect

| Stage                | Target                  |
| -------------------- | ----------------------- |
| Acknowledgement      | 2 business days         |
| Initial assessment   | 5 business days         |
| Fix for a critical   | 14 days                 |
| Fix for high or below| Next scheduled release  |

We will tell you what we found, what we are doing about it, and when. If we
decide something is not a vulnerability, we will say why rather than going
quiet. We are glad to credit you in the advisory, or not, as you prefer.

## Scope

In scope: anything in this repository — the API, the worker, the console, the
migrations, the Helm chart, the Terraform, and the CI workflows.

Particularly interesting, because the product's claims rest on them:

- **Tenant isolation.** Any path that returns one tenant's data to another.
  Row-level security is the boundary; a bypass of it is the highest-severity
  finding this project has.
- **Artifact immutability.** Any way to alter, delete or replace an approved,
  frozen or superseded version, including through a migration or a direct
  database path the application permits.
- **Audit integrity.** Any way to modify, remove or reorder an audit record, or
  to produce a chain that verifies while covering different history — including
  a rewrite that also rewrites the anchors.
- **Separation of duties.** Any way for one principal to both author and approve
  an artifact, for a service account to approve anything, or for an API key to
  hold an approval permission.
- **Evidence.** Any way to produce an approval whose evidence document does not
  match what was approved, or to make evidence unreadable to an auditor who has
  the digest.
- **Authentication.** Token forgery, algorithm confusion, PKCE downgrade, replay
  of an authorization code, or session-cookie forgery in the console.

Out of scope: the development identity provider (`SF_AUTH_DEV_IDP`), which is
not a production component and refuses to start in production; the fixed
credentials in `deploy/docker/docker-compose.yml`, which are local-only by
construction; denial of service through sheer volume; and findings that require
an attacker who already has database superuser access — though we would still
like to hear about anything that such an attacker could do *undetectably*,
because detectability is the property the audit chain exists to provide.

## Supported versions

| Version | Supported                  |
| ------- | -------------------------- |
| 1.0.x   | Yes                        |
| < 1.0   | No — pre-release, upgrade  |

## Handling on our side

- Security fixes are released as patch versions and announced in an advisory
  with a CVE where one applies.
- Container images carry SLSA provenance attestations. A deployment can verify
  that an image was built by this repository's pipeline from a specific commit
  before running it.
- `govulncheck`, `gitleaks` and Trivy run on every pull request and on a
  schedule, so a vulnerability disclosed in a dependency surfaces without anyone
  remembering to look.

## A note on the audit trail

If you find a way to tamper with stored records, please check whether the
tampering survives `specforge-cli verify-audit` against a published anchor, and
say so in the report. The platform does not claim records cannot be altered by
someone with sufficient access; it claims alteration cannot be hidden. A finding
that breaks *detection* is materially more serious than one that breaks
*prevention*, and we will treat it that way.
