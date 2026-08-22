# SpecForge infrastructure

Terraform for the AWS footprint SpecForge needs. The application never creates
infrastructure at run time — the platform's own §28 rule — so everything here
is declarative and reviewable, and the running services are given endpoints and
credentials rather than the permission to make their own.

## What this provisions

| Module     | What it creates                                                        |
| ---------- | ---------------------------------------------------------------------- |
| `network`  | VPC, private and public subnets, NAT, VPC endpoints, security groups   |
| `database` | Aurora PostgreSQL cluster, parameter group, subnet group, backups      |
| `storage`  | S3 buckets for content, evidence and audit anchors, with Object Lock   |
| `cluster`  | EKS cluster, node groups, IRSA roles, addons                           |

## Why the evidence buckets are separate

`storage` creates three buckets, not one, and the two that matter carry S3
Object Lock in **compliance** mode:

- **Content** is content-addressed and rebuildable from the database. Ordinary
  versioning is enough.
- **Evidence** holds approval documents. They are written once at approval and
  are the record an auditor examines. Compliance-mode retention means that even
  the account root cannot shorten it or delete an object before it expires.
- **Audit anchors** hold published chain heads. Their whole purpose is to be
  the reference a database rewrite cannot reach, so they must be outside the
  reach of the credentials the platform itself holds.

Object Lock cannot be enabled on an existing bucket. If these are created
without it, the fix is a new bucket and a migration, not a setting change —
which is why the module refuses to create them with it disabled.

## Layout

```
deploy/terraform
├── modules/
│   ├── network/     VPC and connectivity
│   ├── database/    Aurora PostgreSQL
│   ├── storage/     S3 with Object Lock
│   └── cluster/     EKS
└── envs/
    ├── dev/         one small cluster, relaxed retention
    └── prod/        multi-AZ, long retention, deletion protection
```

## Usage

State is remote and locked. Configure the backend for your account first — the
`backend.tf` in each environment is a placeholder with no bucket name, because
committing one ties this repository to a particular AWS account.

```bash
cd envs/prod
terraform init -backend-config=backend.hcl
terraform plan  -var-file=prod.tfvars
terraform apply -var-file=prod.tfvars
```

## What is deliberately not here

- **Secrets.** No password, key or token is written to a variable file. The
  database module generates its master password into AWS Secrets Manager and
  outputs only the ARN.
- **Kubernetes resources.** The Helm chart owns those. Terraform stops at the
  cluster boundary so a `terraform destroy` cannot take an application release
  with it.
- **DNS and certificates.** These usually live in a separate account with a
  different change process.
