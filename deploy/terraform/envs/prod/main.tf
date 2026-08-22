/**
 * SpecForge production environment.
 *
 * This file is the whole production footprint. It is short on purpose: the
 * modules carry the decisions, and an environment should read as a statement
 * of size and retention rather than a second implementation.
 */

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      "specforge.io/environment" = "prod"
      "specforge.io/managed-by"  = "terraform"
      "specforge.io/repository"  = "specforge/specforge"
    }
  }
}

locals {
  name_prefix = "specforge-prod"
}

# The key that protects the database, the buckets, the cluster's secrets and
# the credentials secret. One key, rotated, so that revoking it revokes access
# to everything at once — which is what an incident response actually needs.
resource "aws_kms_key" "platform" {
  description             = "SpecForge production platform key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "platform" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.platform.key_id
}

module "network" {
  source = "../../modules/network"

  name_prefix        = local.name_prefix
  region             = var.region
  cidr_block         = var.vpc_cidr
  availability_zones = var.availability_zones
  # One NAT per zone: a single gateway would make one zone's failure an outage
  # for the platform's outbound traffic.
  single_nat_gateway = false
  flow_logs_enabled  = true
}

module "storage" {
  source = "../../modules/storage"

  name_prefix         = local.name_prefix
  environment         = "prod"
  kms_key_arn         = aws_kms_key.platform.arn
  object_lock_enabled = true
  retention_days      = 2555 # seven years
  allow_destroy       = false
}

module "database" {
  source = "../../modules/database"

  name_prefix        = local.name_prefix
  environment        = "prod"
  private_subnet_ids = module.network.private_subnet_ids
  security_group_ids = [module.network.database_security_group_id]
  kms_key_arn        = aws_kms_key.platform.arn
  instance_count     = 3
  instance_class     = var.database_instance_class
}

module "cluster" {
  source = "../../modules/cluster"

  name_prefix            = local.name_prefix
  private_subnet_ids     = module.network.private_subnet_ids
  node_security_group_id = module.network.node_security_group_id
  kms_key_arn            = aws_kms_key.platform.arn

  # Private control plane. Access is through the account's existing VPN path.
  public_endpoint_enabled = false

  instance_types = var.node_instance_types
  desired_size   = 4
  min_size       = 3
  max_size       = 24

  content_bucket_arn      = module.storage.bucket_arns.content
  evidence_bucket_arn     = module.storage.bucket_arns.evidence
  audit_anchor_bucket_arn = module.storage.bucket_arns.audit_anchors

  secret_arns = [module.database.credentials_secret_arn]

  addons = {
    "vpc-cni"            = var.addon_versions.vpc_cni
    "coredns"            = var.addon_versions.coredns
    "kube-proxy"         = var.addon_versions.kube_proxy
    "aws-ebs-csi-driver" = var.addon_versions.ebs_csi
  }
}
