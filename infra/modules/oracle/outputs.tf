output "aws_region" {
  description = "Region this module instance deployed into"
  value       = var.aws_region
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

output "github_oidc_role_arn" {
  value = aws_iam_role.github_ci.arn
}

output "release_kms_key_arn" {
  description = "ARN of the EIF release signing KMS key"
  value       = aws_kms_key.release.arn
}

output "release_kms_alias" {
  description = "Alias of the release signing KMS key (used by aws kms sign / verify)"
  value       = aws_kms_alias.release.name
}

output "sealing_kms_key_arn" {
  description = "ARN of the enclave-key sealing KMS key"
  value       = aws_kms_key.sealing.arn
}

output "sealing_kms_alias" {
  description = "Alias of the sealing KMS key"
  value       = aws_kms_alias.sealing.name
}

output "alb_dns_name" {
  description = "ALB DNS name — use this to access the pull API directly, or as the CNAME target for the oracle domain"
  value       = aws_lb.oracle.dns_name
}

# ─── External DNS (Namecheap etc.) bootstrap ──────────────────
# If `var.domain_name` is set, Terraform creates the ACM cert with
# DNS-validation. The certificate stays in `PENDING_VALIDATION` until
# the operator adds the CNAME records below at the registrar. After
# DNS propagates (~minutes for Namecheap), `terraform apply` again to
# unblock the validation, attach HTTPS listener, and flip HTTP to
# 301-redirect.
output "acm_dns_validation_records" {
  description = "CNAME records to add at the registrar (e.g. Namecheap) to validate the ACM certificate. After adding, run `terraform apply` again to finish issuance."
  value = var.domain_name == "" ? [] : [
    for opt in aws_acm_certificate.oracle[0].domain_validation_options : {
      cname_name  = opt.resource_record_name
      cname_value = opt.resource_record_value
      type        = opt.resource_record_type
    }
  ]
}

output "domain_cname_target" {
  description = "Where to point the domain at your registrar — add a CNAME (or ALIAS, if supported) from var.domain_name to this ALB DNS."
  value       = var.domain_name == "" ? null : aws_lb.oracle.dns_name
}
