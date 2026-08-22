variable "name_prefix" {
  type        = string
  description = "Prefix for resource names."
}

variable "environment" {
  type        = string
  description = "dev, staging or prod. Controls retention, deletion protection and snapshot behaviour."

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets for the cluster. The database is never placed in a public subnet."

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "At least two subnets in different availability zones are required."
  }
}

variable "security_group_ids" {
  type        = list(string)
  description = "Security groups permitting 5432 from the application nodes only."
}

variable "kms_key_arn" {
  type        = string
  description = "Customer-managed key for storage, snapshots and the credentials secret."
}

variable "engine_version" {
  type        = string
  description = "Aurora PostgreSQL engine version."
  default     = "16.4"
}

variable "parameter_group_family" {
  type        = string
  description = "Parameter group family matching the engine version."
  default     = "aurora-postgresql16"
}

variable "database_name" {
  type        = string
  default     = "specforge"
}

variable "master_username" {
  type        = string
  default     = "specforge_admin"
}

variable "instance_count" {
  type        = number
  description = "Writer plus readers. Two or more in production so a failover has somewhere to go."
  default     = 2

  validation {
    condition     = var.instance_count >= 1
    error_message = "At least one instance is required."
  }
}

variable "instance_class" {
  type    = string
  default = "db.r6g.large"
}

variable "monitoring_role_arn" {
  type        = string
  description = "IAM role for enhanced monitoring."
  default     = null
}

variable "tags" {
  type    = map(string)
  default = {}
}
