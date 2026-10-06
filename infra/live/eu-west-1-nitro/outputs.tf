output "alb_dns_name" {
  description = "EU ALB DNS: CloudFront failover origin for the edge name."
  value       = module.fleet.alb_dns_name
}

output "prod_asg_name" {
  value = module.fleet.asg_name
}

output "vpc_id" {
  value = module.fleet.vpc_id
}

output "vpc_cidr" {
  value = module.fleet.vpc_cidr
}

output "peering_connection_id" {
  value = aws_vpc_peering_connection.us.id
}

output "acm_dns_validation_records" {
  description = "CNAMEs to validate the ACM cert outside kaskad-tf. Empty while domain_name is unset."
  value       = module.fleet.acm_dns_validation_records
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
