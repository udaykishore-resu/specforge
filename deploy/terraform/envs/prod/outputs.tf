output "cluster_name" {
  value = module.cluster.cluster_name
}

output "database_secret_arn" {
  description = "Create the Kubernetes Secret the Helm chart expects from this."
  value       = module.database.credentials_secret_arn
}

output "platform_role_arn" {
  description = "Set serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn to this in the Helm values."
  value       = module.cluster.platform_role_arn
}

output "buckets" {
  value = {
    content       = module.storage.content_bucket
    evidence      = module.storage.evidence_bucket
    audit_anchors = module.storage.audit_anchor_bucket
  }
}
