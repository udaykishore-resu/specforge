/**
 * Object storage for SpecForge.
 *
 * Three buckets with deliberately different guarantees:
 *
 *   content   Content-addressed artifact bodies. Rebuildable, so versioning
 *             and lifecycle rules are enough.
 *   evidence  Approval evidence documents. Written once at approval; the
 *             record an auditor reads. Object Lock in compliance mode.
 *   anchors   Published audit chain heads. Their purpose is to be the external
 *             reference that a database rewrite cannot match, so they must be
 *             beyond the reach of the platform's own credentials.
 *
 * Object Lock cannot be turned on after a bucket exists. That is why the
 * variable defaults to true and the precondition below refuses to create the
 * evidence buckets without it: getting this wrong is not a setting to fix
 * later, it is a bucket to recreate and a migration to run.
 */

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }
}

locals {
  tags = merge(var.tags, {
    "specforge.io/component"  = "storage"
    "specforge.io/managed-by" = "terraform"
  })
}

# ----------------------------------------------------------------- content ---
resource "aws_s3_bucket" "content" {
  bucket = "${var.name_prefix}-content"
  tags   = merge(local.tags, { "specforge.io/purpose" = "artifact-content" })
}

resource "aws_s3_bucket_versioning" "content" {
  bucket = aws_s3_bucket.content.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "content" {
  bucket = aws_s3_bucket.content.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "content" {
  bucket                  = aws_s3_bucket.content.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "content" {
  bucket = aws_s3_bucket.content.id

  rule {
    id     = "abort-incomplete-uploads"
    status = "Enabled"
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "expire-noncurrent"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# --------------------------------------------------- evidence and anchors ---
resource "aws_s3_bucket" "locked" {
  for_each = toset(["evidence", "audit-anchors"])

  bucket = "${var.name_prefix}-${each.key}"
  # Object Lock requires versioning and can only be set at creation.
  object_lock_enabled = var.object_lock_enabled

  # A deletable evidence bucket is not evidence storage. In production the
  # bucket must survive a `terraform destroy` of everything around it.
  force_destroy = var.allow_destroy

  tags = merge(local.tags, {
    "specforge.io/purpose"   = each.key
    "specforge.io/immutable" = "true"
  })

  lifecycle {
    precondition {
      condition     = var.object_lock_enabled
      error_message = "object_lock_enabled must be true. Approval evidence and audit anchors are written once; without Object Lock they are ordinary, overwritable objects and the platform's integrity claims do not hold."
    }
    precondition {
      condition     = !var.allow_destroy || var.environment != "prod"
      error_message = "allow_destroy must be false in prod: this bucket holds the records an auditor relies on."
    }
    prevent_destroy = false # set per environment via allow_destroy
  }
}

resource "aws_s3_bucket_versioning" "locked" {
  for_each = aws_s3_bucket.locked

  bucket = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "locked" {
  for_each = aws_s3_bucket.locked

  bucket = each.value.id

  rule {
    default_retention {
      # COMPLIANCE, not GOVERNANCE: under GOVERNANCE a sufficiently privileged
      # principal can shorten the retention, which is exactly the principal an
      # attacker tries to become.
      mode = "COMPLIANCE"
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.locked]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "locked" {
  for_each = aws_s3_bucket.locked

  bucket = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "locked" {
  for_each = aws_s3_bucket.locked

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Deny any attempt to delete a locked object, on top of Object Lock itself.
# Defence in depth: the bucket policy makes the intent explicit in a place a
# reviewer will read, and produces a clear AccessDenied rather than a confusing
# retention error.
resource "aws_s3_bucket_policy" "locked" {
  for_each = aws_s3_bucket.locked

  bucket = each.value.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyObjectDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:PutObjectRetention",
          "s3:PutBucketObjectLockConfiguration",
        ]
        Resource = ["${each.value.arn}/*", each.value.arn]
      },
      {
        Sid       = "DenyUnencryptedTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["${each.value.arn}/*", each.value.arn]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })
}

# Access logs for the evidence buckets go to a separate bucket, because "who
# read the approval evidence" is itself an audit question.
resource "aws_s3_bucket_logging" "locked" {
  for_each = var.access_log_bucket == "" ? {} : aws_s3_bucket.locked

  bucket        = each.value.id
  target_bucket = var.access_log_bucket
  target_prefix = "s3/${each.value.id}/"
}
