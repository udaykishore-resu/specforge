variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "availability_zones" {
  type    = list(string)
  default = ["eu-west-1a", "eu-west-1b"]
}

variable "admin_cidrs" {
  description = "CIDRs permitted to reach the development control plane. Never 0.0.0.0/0, even here."
  type        = list(string)

  validation {
    condition     = !contains(var.admin_cidrs, "0.0.0.0/0")
    error_message = "Do not expose the Kubernetes control plane to the internet."
  }
}

variable "addon_versions" {
  type    = map(string)
  default = {}
}
