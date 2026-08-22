output "cluster_name"     { value = aws_eks_cluster.this.name }
output "cluster_endpoint" { value = aws_eks_cluster.this.endpoint }

output "cluster_ca_data" {
  value     = aws_eks_cluster.this.certificate_authority[0].data
  sensitive = true
}

output "oidc_provider_arn" { value = aws_iam_openid_connect_provider.this.arn }

output "platform_role_arn" {
  description = "Annotate the platform's ServiceAccount with this so pods assume it via IRSA."
  value       = aws_iam_role.platform.arn
}
