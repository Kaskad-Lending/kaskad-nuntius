output "distribution_id" {
  value = aws_cloudfront_distribution.nuntius.id
}

output "distribution_domain_name" {
  description = "CNAME target for the edge name."
  value       = aws_cloudfront_distribution.nuntius.domain_name
}

output "dns_records" {
  description = "Records to add outside kaskad-tf: edge cert validation (both regions) and the edge CNAME."
  value = concat(
    distinct(concat(local.us.edge_dns_validation_records, local.eu.edge_dns_validation_records)),
    [{
      cname_name  = "${local.edge.domain}."
      cname_value = aws_cloudfront_distribution.nuntius.domain_name
      type        = "CNAME"
    }],
  )
}
