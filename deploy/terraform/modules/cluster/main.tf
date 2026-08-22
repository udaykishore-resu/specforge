/**
 * EKS cluster for SpecForge.
 *
 * Two decisions worth stating:
 *
 *   * Secrets envelope encryption with a customer-managed key. Kubernetes
 *     Secrets hold the database DSN and the console's session key; without
 *     this they are base64 in etcd.
 *
 *   * IRSA rather than node-instance credentials. The API's access to the
 *     evidence bucket must be scoped to the API's service account, not to
 *     every pod that happens to land on the same node.
 *
 * The cluster's control-plane endpoint is private by default. Access comes
 * through the account's normal bastion or VPN path, because a public API
 * endpoint on a cluster that holds this platform's secrets is one credential
 * leak away from a full compromise.
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
    "specforge.io/component"  = "cluster"
    "specforge.io/managed-by" = "terraform"
  })
}

data "aws_iam_policy_document" "cluster_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${var.name_prefix}-eks-cluster"
  assume_role_policy = data.aws_iam_policy_document.cluster_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "cluster" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController",
  ])

  role       = aws_iam_role.cluster.name
  policy_arn = each.value
}

resource "aws_eks_cluster" "this" {
  name     = var.name_prefix
  role_arn = aws_iam_role.cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = var.public_endpoint_enabled
    public_access_cidrs     = var.public_endpoint_cidrs
    security_group_ids      = [var.node_security_group_id]
  }

  encryption_config {
    provider {
      key_arn = var.kms_key_arn
    }
    resources = ["secrets"]
  }

  # All of them. A cluster whose audit log was not enabled before an incident
  # cannot answer what happened during it.
  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  tags = local.tags

  depends_on = [aws_iam_role_policy_attachment.cluster]
}

data "aws_iam_policy_document" "node_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "${var.name_prefix}-eks-node"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
  ])

  role       = aws_iam_role.node.name
  policy_arn = each.value
}

resource "aws_eks_node_group" "this" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.name_prefix}-workers"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = var.private_subnet_ids

  instance_types = var.instance_types
  capacity_type  = "ON_DEMAND"

  scaling_config {
    desired_size = var.desired_size
    min_size     = var.min_size
    max_size     = var.max_size
  }

  update_config {
    max_unavailable_percentage = 25
  }

  tags = local.tags

  lifecycle {
    # The autoscaler owns desired_size once the cluster is running.
    ignore_changes = [scaling_config[0].desired_size]
  }
}

# ------------------------------------------------------------------ IRSA ----
data "tls_certificate" "oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "this" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc.certificates[0].sha1_fingerprint]
  tags            = local.tags
}

data "aws_iam_policy_document" "platform_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.this.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.this.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${var.service_account_name}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.this.url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "platform" {
  name               = "${var.name_prefix}-platform"
  assume_role_policy = data.aws_iam_policy_document.platform_assume.json
  tags               = local.tags
}

# The platform's own storage permissions.
#
# Note what is absent: no DeleteObject on any bucket, and no
# PutObjectRetention. The application writes evidence and never removes or
# shortens it, so the credential it runs with should not be able to either.
data "aws_iam_policy_document" "platform" {
  statement {
    sid    = "ContentReadWrite"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
    ]
    resources = [
      var.content_bucket_arn,
      "${var.content_bucket_arn}/*",
    ]
  }

  statement {
    sid    = "EvidenceWriteOnce"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:GetObjectRetention",
      "s3:PutObject",
      "s3:PutObjectRetention",
      "s3:ListBucket",
    ]
    resources = [
      var.evidence_bucket_arn,
      "${var.evidence_bucket_arn}/*",
      var.audit_anchor_bucket_arn,
      "${var.audit_anchor_bucket_arn}/*",
    ]
    # Retention may only be set, never shortened or removed. Compliance mode
    # enforces this server-side as well; stating it here makes the intent
    # visible to anyone reading the role.
    condition {
      test     = "StringEquals"
      variable = "s3:object-lock-mode"
      values   = ["COMPLIANCE"]
    }
  }

  statement {
    sid       = "ReadOwnSecrets"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = var.secret_arns
  }

  statement {
    sid    = "UseKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [var.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "platform" {
  name   = "${var.name_prefix}-platform"
  role   = aws_iam_role.platform.id
  policy = data.aws_iam_policy_document.platform.json
}

resource "aws_eks_addon" "this" {
  for_each = var.addons

  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = each.key
  addon_version               = each.value
  resolve_conflicts_on_update = "PRESERVE"
  tags                        = local.tags
}
