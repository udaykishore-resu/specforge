output "vpc_id" { value = aws_vpc.this.id }
output "vpc_cidr" { value = aws_vpc.this.cidr_block }
output "private_subnet_ids" { value = aws_subnet.private[*].id }
output "public_subnet_ids" { value = aws_subnet.public[*].id }

output "database_security_group_id" {
  description = "Attach to the Aurora cluster; permits 5432 from the nodes only."
  value       = aws_security_group.database.id
}

output "node_security_group_id" {
  value = aws_security_group.nodes.id
}
