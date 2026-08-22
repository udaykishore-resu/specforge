output "cluster_endpoint" {
  description = "Writer endpoint."
  value       = aws_rds_cluster.this.endpoint
}

output "reader_endpoint" {
  description = "Reader endpoint, for read-only queries such as audit export."
  value       = aws_rds_cluster.this.reader_endpoint
}

output "credentials_secret_arn" {
  description = <<-EOT
    ARN of the Secrets Manager secret holding the master credentials and the
    DSN. The value itself is never an output: an output lands in state, in
    plan files, and in whatever CI system prints them.
  EOT
  value       = aws_secretsmanager_secret.master.arn
}

output "database_name" {
  value = var.database_name
}
