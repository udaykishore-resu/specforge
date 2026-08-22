variable "name_prefix" {
  description = "Prefix for bucket names. Must be globally unique across S3."
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod). Controls the safety preconditions."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key for bucket encryption."
  type        = string
}

variable "object_lock_enabled" {
  description = <<-EOT
    Enable S3 Object Lock on the evidence and audit-anchor buckets.

    Defaults to true and should stay true. Object Lock cannot be enabled after
    a bucket is created, so disabling it here is a decision that can only be
    reversed by creating new buckets and migrating.
  EOT
  type        = bool
  default     = true
}

variable "retention_days" {
  description = "Default compliance-mode retention for evidence and anchors. Seven years by default, matching the platform's evidence retention."
  type        = number
  default     = 2555

  validation {
    condition     = var.retention_days >= 365
    error_message = "Retention below one year does not meet the platform's evidence commitments."
  }
}

variable "allow_destroy" {
  description = "Permit `terraform destroy` to remove the locked buckets. Never true in prod."
  type        = bool
  default     = false
}

variable "access_log_bucket" {
  description = "Bucket for S3 access logs. Empty disables access logging."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
