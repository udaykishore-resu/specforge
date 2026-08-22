output "content_bucket" {
  description = "Bucket holding content-addressed artifact bodies."
  value       = aws_s3_bucket.content.id
}

output "evidence_bucket" {
  description = "Write-once bucket holding approval evidence."
  value       = aws_s3_bucket.locked["evidence"].id
}

output "audit_anchor_bucket" {
  description = "Write-once bucket holding published audit chain anchors."
  value       = aws_s3_bucket.locked["audit-anchors"].id
}

output "bucket_arns" {
  description = "ARNs of all three buckets, for IAM policy attachment."
  value = {
    content       = aws_s3_bucket.content.arn
    evidence      = aws_s3_bucket.locked["evidence"].arn
    audit_anchors = aws_s3_bucket.locked["audit-anchors"].arn
  }
}

output "retention_days" {
  description = "Compliance-mode retention in force on the locked buckets."
  value       = var.retention_days
}
