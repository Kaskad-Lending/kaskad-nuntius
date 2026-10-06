output "aws_region" {
  value = var.aws_region
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "prod_asg_name" {
  value = module.fleet.asg_name
}

output "builder_instance_id" {
  value = aws_instance.builder.id
}

output "eif_bucket" {
  value = aws_s3_bucket.eif.bucket
}

output "prod_security_group" {
  value = module.fleet.prod_security_group_id
}

output "github_ci_role_arn" {
  value = aws_iam_role.github_ci.arn
}

output "alb_dns_name" {
  description = "ALB DNS: CloudFront origin for the edge name"
  value       = module.fleet.alb_dns_name
}

output "acm_dns_validation_records" {
  description = "CNAMEs to validate the ACM cert, added outside kaskad-tf. Empty while domain_name is unset."
  value       = module.fleet.acm_dns_validation_records
}

output "vpc_id" {
  value = module.fleet.vpc_id
}

output "vpc_cidr" {
  value = module.fleet.vpc_cidr
}

output "public_route_table_id" {
  description = "The EU root adds its peering route here."
  value       = module.fleet.public_route_table_id
}

output "edge_certificate_arn" {
  value = module.fleet.edge_certificate_arn
}

output "edge_dns_validation_records" {
  description = "CNAMEs that validate the edge (nuntius) cert, added outside kaskad-tf."
  value       = module.fleet.edge_dns_validation_records
}

output "edge_origin_header" {
  value = module.fleet.edge_origin_header
}

output "edge_origin_token" {
  value     = module.fleet.edge_origin_token
  sensitive = true
}
