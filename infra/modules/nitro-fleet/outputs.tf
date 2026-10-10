output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr" {
  value = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  value = [aws_subnet.public_a.id, aws_subnet.public_b.id]
}

output "public_route_table_id" {
  value = aws_route_table.public.id
}

output "prod_security_group_id" {
  value = aws_security_group.prod.id
}

output "asg_name" {
  value = aws_autoscaling_group.prod.name
}

output "launch_template_id" {
  value = aws_launch_template.prod.id
}

output "alb_dns_name" {
  description = "ALB DNS: the CloudFront origin when edge-only, else the pull API endpoint."
  value       = aws_lb.nitro.dns_name
}

output "acm_dns_validation_records" {
  description = "CNAMEs that validate the module's ACM cert, added outside kaskad-tf. Empty without domain_name or with certificate_arn."
  value = length(aws_acm_certificate.nitro) == 0 ? [] : [
    for opt in aws_acm_certificate.nitro[0].domain_validation_options : {
      cname_name  = opt.resource_record_name
      cname_value = opt.resource_record_value
      type        = opt.resource_record_type
    }
  ]
}

output "edge_certificate_arn" {
  description = "Edge ACM cert; in us-east-1 it doubles as the CloudFront viewer cert. Empty without an edge."
  value       = local.edge_enabled ? aws_acm_certificate.edge[0].arn : ""
}

output "edge_dns_validation_records" {
  description = "CNAMEs that validate the edge cert, added outside kaskad-tf. Empty without an edge."
  value = local.edge_enabled ? [
    for opt in aws_acm_certificate.edge[0].domain_validation_options : {
      cname_name  = opt.resource_record_name
      cname_value = opt.resource_record_value
      type        = opt.resource_record_type
    }
  ] : []
}

output "edge_origin_header" {
  description = "Header name the edge must send with edge_origin_token."
  value       = local.edge_header
}

output "edge_origin_token" {
  description = "Value of edge_origin_header that this region's ALB accepts for the edge Host."
  value       = local.edge_enabled ? random_password.edge_origin[0].result : ""
  sensitive   = true
}
