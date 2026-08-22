/**
 * SpecForge development environment.
 *
 * Smaller and cheaper than production, and it says so in the values rather
 * than in the modules: one NAT gateway, one database instance, short backup
 * retention. What does not change is Object Lock on the evidence buckets —
 * a development environment where evidence can be deleted teaches people the
 * wrong thing about how the platform behaves.
 */

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.60" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
    tls    = { source = "hashicorp/tls", version = "~> 4.0" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      "specforge.io/environment" = "dev"
      "specforge.io/managed-by"  = "terraform"
    }
  }
}

locals {
  name_prefix = "specforge-dev"
}

resource "aws_kms_key" "platform" {
  description             = "SpecForge development platform key"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

module "network" {
  source = "../../modules/network"

  name_prefix        = local.name_prefix
  region             = var.region
  cidr_block         = "10.61.0.0/16"
  availability_zones = var.availability_zones
  single_nat_gateway = true
  flow_logs_enabled  = false
}

module "storage" {
  source = "../../modules/storage"

  name_prefix         = local.name_prefix
  environment         = "dev"
  kms_key_arn         = aws_kms_key.platform.arn
  object_lock_enabled = true
  # One year, the module's floor. Long enough that the behaviour is real,
  # short enough that a development account does not accumulate forever.
  retention_days = 365
  allow_destroy  = true
}

module "database" {
  source = "../../modules/database"

  name_prefix        = local.name_prefix
  environment        = "dev"
  private_subnet_ids = module.network.private_subnet_ids
  security_group_ids = [module.network.database_security_group_id]
  kms_key_arn        = aws_kms_key.platform.arn
  instance_count     = 1
  instance_class     = "db.t4g.medium"
}

module "cluster" {
  source = "../../modules/cluster"

  name_prefix            = local.name_prefix
  private_subnet_ids     = module.network.private_subnet_ids
  node_security_group_id = module.network.node_security_group_id
  kms_key_arn            = aws_kms_key.platform.arn

  public_endpoint_enabled = true
  public_endpoint_cidrs   = var.admin_cidrs

  instance_types = ["t3.large"]
  desired_size   = 2
  min_size       = 1
  max_size       = 6

  content_bucket_arn      = module.storage.bucket_arns.content
  evidence_bucket_arn     = module.storage.bucket_arns.evidence
  audit_anchor_bucket_arn = module.storage.bucket_arns.audit_anchors

  secret_arns = [module.database.credentials_secret_arn]

  addons = var.addon_versions
}
