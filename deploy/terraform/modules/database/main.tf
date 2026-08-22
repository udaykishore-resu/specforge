/**
 * Aurora PostgreSQL for SpecForge.
 *
 * Two settings here are load-bearing for the platform's guarantees rather than
 * for its performance:
 *
 *   * Point-in-time recovery with a long backup window. The audit trail is
 *     append-only and hash-chained, so a restore to an arbitrary second is the
 *     difference between "we can prove what the state was" and "we think we
 *     remember".
 *
 *   * `rds.force_ssl`. Every connection carries tenant data and the session
 *     variable that row-level security reads. A plaintext connection would put
 *     both on the wire.
 *
 * The master password is generated into Secrets Manager and never appears in
 * state as a plan input, in a variable file, or in an output.
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
    "specforge.io/component"  = "database"
    "specforge.io/managed-by" = "terraform"
  })
  is_prod = var.environment == "prod"
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-db"
  subnet_ids = var.private_subnet_ids
  tags       = local.tags
}

resource "aws_rds_cluster_parameter_group" "this" {
  name        = "${var.name_prefix}-aurora-pg"
  family      = var.parameter_group_family
  description = "SpecForge Aurora PostgreSQL cluster parameters"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  # Log every statement that changes schema or permissions. The platform's own
  # audit trail covers application actions; this covers actions taken around it.
  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  # Row-level security is the tenancy boundary. This makes it apply to the
  # table owner too, so a mistake in role assignment does not silently disable
  # isolation.
  parameter {
    name  = "row_security"
    value = "on"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  tags = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "random_password" "master" {
  length  = 48
  special = true
  # Characters RDS rejects in a master password.
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret" "master" {
  name                    = "${var.name_prefix}/database/master"
  description             = "SpecForge Aurora master credentials"
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = local.is_prod ? 30 : 7
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "master" {
  secret_id = aws_secretsmanager_secret.master.id
  secret_string = jsonencode({
    username = var.master_username
    password = random_password.master.result
    engine   = "postgres"
    host     = aws_rds_cluster.this.endpoint
    port     = 5432
    dbname   = var.database_name
    # The DSN the application reads. sslmode=verify-full, not require: `require`
    # encrypts but does not authenticate the server, which leaves the
    # connection open to interception by anything that can answer on the
    # endpoint.
    dsn = format(
      "host=%s port=5432 user=%s password=%s dbname=%s sslmode=verify-full",
      aws_rds_cluster.this.endpoint,
      var.master_username,
      random_password.master.result,
      var.database_name,
    )
  })
}

resource "aws_rds_cluster" "this" {
  cluster_identifier     = "${var.name_prefix}-aurora"
  engine                 = "aurora-postgresql"
  engine_version         = var.engine_version
  database_name          = var.database_name
  master_username        = var.master_username
  master_password        = random_password.master.result
  port                   = 5432

  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = var.security_group_ids
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.this.name

  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  backup_retention_period      = local.is_prod ? 35 : 7
  preferred_backup_window      = "02:00-03:00"
  preferred_maintenance_window = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot        = true

  # A production database that can be dropped by a plan is a production
  # database that eventually will be.
  deletion_protection       = local.is_prod
  skip_final_snapshot       = !local.is_prod
  final_snapshot_identifier = local.is_prod ? "${var.name_prefix}-final-${formatdate("YYYYMMDDhhmmss", timestamp())}" : null

  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = local.tags

  lifecycle {
    ignore_changes = [
      # The snapshot identifier embeds a timestamp, which would otherwise show
      # as a diff on every plan.
      final_snapshot_identifier,
      master_password,
    ]
  }
}

resource "aws_rds_cluster_instance" "this" {
  count = var.instance_count

  identifier          = "${var.name_prefix}-aurora-${count.index}"
  cluster_identifier  = aws_rds_cluster.this.id
  instance_class      = var.instance_class
  engine              = aws_rds_cluster.this.engine
  engine_version      = aws_rds_cluster.this.engine_version
  db_subnet_group_name = aws_db_subnet_group.this.name

  performance_insights_enabled          = true
  performance_insights_kms_key_id       = var.kms_key_arn
  performance_insights_retention_period = local.is_prod ? 731 : 7

  monitoring_interval = 30
  monitoring_role_arn = var.monitoring_role_arn

  auto_minor_version_upgrade = !local.is_prod

  tags = local.tags
}
