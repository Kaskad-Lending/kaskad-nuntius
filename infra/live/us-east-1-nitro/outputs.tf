output "aws_region" {
  value = var.aws_region
}

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "prod_asg_name" {
  value = aws_autoscaling_group.prod.name
}

output "builder_instance_id" {
  value = aws_instance.builder.id
}

output "eif_bucket" {
  value = aws_s3_bucket.eif.bucket
}

output "prod_security_group" {
  value = aws_security_group.prod.id
}

output "github_ci_role_arn" {
  value = aws_iam_role.github_ci.arn
}

output "release_kms_key_arn" {
  description = "EIF release signing KMS key ARN"
  value       = aws_kms_key.release.arn
}

output "release_kms_alias" {
  description = "EIF release signing KMS alias"
  value       = aws_kms_alias.release.name
}

output "alb_dns_name" {
  description = "ALB DNS — the pull API endpoint (bare DNS while domain_name is empty)"
  value       = aws_lb.nitro.dns_name
}

output "acm_dns_validation_records" {
  description = "CNAMEs to validate the ACM cert, added outside kaskad-tf. Empty while domain_name is unset."
  value = var.domain_name == "" ? [] : [
    for opt in aws_acm_certificate.nitro[0].domain_validation_options : {
      cname_name  = opt.resource_record_name
      cname_value = opt.resource_record_value
      type        = opt.resource_record_type
    }
  ]
}
