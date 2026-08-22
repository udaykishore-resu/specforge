variable "name_prefix" { type = string }

variable "kubernetes_version" {
  type    = string
  default = "1.31"
}

variable "private_subnet_ids"     { type = list(string) }
variable "node_security_group_id" { type = string }
variable "kms_key_arn"            { type = string }

variable "public_endpoint_enabled" {
  type        = bool
  description = "Expose the control-plane endpoint publicly. Default false: this cluster holds the platform's secrets."
  default     = false
}

variable "public_endpoint_cidrs" {
  type    = list(string)
  default = []
}

variable "instance_types" {
  type    = list(string)
  default = ["m6i.large"]
}

variable "desired_size" {
  type    = number
  default = 3
}

variable "min_size" {
  type    = number
  default = 2
}

variable "max_size" {
  type    = number
  default = 10
}

variable "namespace" {
  type        = string
  description = "Namespace the platform runs in, used to scope the IRSA trust policy."
  default     = "specforge"
}

variable "service_account_name" {
  type    = string
  default = "specforge"
}

variable "content_bucket_arn"      { type = string }
variable "evidence_bucket_arn"     { type = string }
variable "audit_anchor_bucket_arn" { type = string }

variable "secret_arns" {
  type        = list(string)
  description = "Secrets the platform may read: the database DSN and the console session key."
  default     = []
}

variable "addons" {
  type        = map(string)
  description = "EKS managed addons and their versions."
  default     = {}
}

variable "tags" {
  type    = map(string)
  default = {}
}
