variable "name_prefix" { type = string }
variable "region" { type = string }

variable "cidr_block" {
  type    = string
  default = "10.60.0.0/16"
}

variable "availability_zones" {
  type        = list(string)
  description = "At least two, so the database and the cluster can survive losing one."

  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "At least two availability zones are required."
  }
}

variable "single_nat_gateway" {
  type        = bool
  description = "One NAT gateway instead of one per zone. Cheaper, and a single point of failure — acceptable in dev, not in prod."
  default     = false
}

variable "interface_endpoints" {
  type        = list(string)
  description = "AWS services reached over private endpoints rather than the internet."
  default = [
    "secretsmanager",
    "kms",
    "ecr.api",
    "ecr.dkr",
    "logs",
    "sts",
    "monitoring",
  ]
}

variable "flow_logs_enabled" {
  type    = bool
  default = true
}

variable "flow_logs_bucket_arn" {
  type    = string
  default = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}
