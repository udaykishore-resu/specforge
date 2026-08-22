/**
 * Network for SpecForge.
 *
 * The shape follows from one requirement: the platform's egress is
 * default-deny, and everything it legitimately needs — S3, Secrets Manager,
 * KMS, ECR, CloudWatch — is reached over VPC endpoints rather than the public
 * internet. Approval evidence travelling to S3 should never leave the AWS
 * network, and the NAT gateway exists only for package and image pulls during
 * node bootstrap.
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
    "specforge.io/component"  = "network"
    "specforge.io/managed-by" = "terraform"
  })
  az_count = length(var.availability_zones)
}

resource "aws_vpc" "this" {
  cidr_block           = var.cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = var.name_prefix })
}

resource "aws_subnet" "private" {
  count = local.az_count

  vpc_id            = aws_vpc.this.id
  availability_zone = var.availability_zones[count.index]
  cidr_block        = cidrsubnet(var.cidr_block, 4, count.index)

  tags = merge(local.tags, {
    Name                              = "${var.name_prefix}-private-${count.index}"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

resource "aws_subnet" "public" {
  count = local.az_count

  vpc_id                  = aws_vpc.this.id
  availability_zone       = var.availability_zones[count.index]
  cidr_block              = cidrsubnet(var.cidr_block, 4, count.index + local.az_count)
  map_public_ip_on_launch = false # explicit assignment only

  tags = merge(local.tags, {
    Name                     = "${var.name_prefix}-public-${count.index}"
    "kubernetes.io/role/elb" = "1"
  })
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = local.tags
}

resource "aws_eip" "nat" {
  count  = var.single_nat_gateway ? 1 : local.az_count
  domain = "vpc"
  tags   = local.tags
}

resource "aws_nat_gateway" "this" {
  count = var.single_nat_gateway ? 1 : local.az_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = merge(local.tags, { Name = "${var.name_prefix}-nat-${count.index}" })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }
  tags = merge(local.tags, { Name = "${var.name_prefix}-public" })
}

resource "aws_route_table_association" "public" {
  count          = local.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count  = local.az_count
  vpc_id = aws_vpc.this.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.this[var.single_nat_gateway ? 0 : count.index].id
  }

  tags = merge(local.tags, { Name = "${var.name_prefix}-private-${count.index}" })
}

resource "aws_route_table_association" "private" {
  count          = local.az_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ------------------------------------------------------------- endpoints ----
# Gateway endpoints are free and keep S3 traffic off the NAT path entirely.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id
  tags              = merge(local.tags, { Name = "${var.name_prefix}-s3" })
}

resource "aws_security_group" "endpoints" {
  name        = "${var.name_prefix}-vpce"
  description = "Interface VPC endpoints"
  vpc_id      = aws_vpc.this.id

  ingress {
    description = "HTTPS from within the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.cidr_block]
  }

  tags = local.tags
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(var.interface_endpoints)

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = merge(local.tags, { Name = "${var.name_prefix}-${each.key}" })
}

# --------------------------------------------------------- security groups --
resource "aws_security_group" "database" {
  name        = "${var.name_prefix}-database"
  description = "Aurora: PostgreSQL from the application nodes only"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "PostgreSQL from the cluster nodes"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.nodes.id]
  }

  tags = local.tags
}

resource "aws_security_group" "nodes" {
  name        = "${var.name_prefix}-nodes"
  description = "Cluster nodes"
  vpc_id      = aws_vpc.this.id

  egress {
    description = "HTTPS out, for endpoints, image pulls and the identity provider"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "PostgreSQL to the database"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.cidr_block]
  }

  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.cidr_block]
  }

  tags = local.tags
}

# VPC flow logs. Not for troubleshooting: for answering "what left the network
# and when" after an incident, which is a question that cannot be answered
# retrospectively unless the logs were already on.
resource "aws_flow_log" "this" {
  count = var.flow_logs_enabled ? 1 : 0

  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = var.flow_logs_bucket_arn
  tags                 = local.tags
}
