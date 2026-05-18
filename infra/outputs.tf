output "us_east_1" {
  description = "Key resources for the us-east-1 oracle deployment"
  value = {
    asg            = module.oracle_us_east_1.prod_asg_name
    builder        = module.oracle_us_east_1.builder_instance_id
    alb_dns        = module.oracle_us_east_1.alb_dns_name
    eif_bucket     = module.oracle_us_east_1.eif_bucket
    github_ci_role = module.oracle_us_east_1.github_oidc_role_arn
    sealing_kms    = module.oracle_us_east_1.sealing_kms_alias
  }
}

output "eu_west_1" {
  description = "Key resources for the eu-west-1 oracle deployment"
  value = {
    asg            = module.oracle_eu_west_1.prod_asg_name
    builder        = module.oracle_eu_west_1.builder_instance_id
    alb_dns        = module.oracle_eu_west_1.alb_dns_name
    eif_bucket     = module.oracle_eu_west_1.eif_bucket
    github_ci_role = module.oracle_eu_west_1.github_oidc_role_arn
    sealing_kms    = module.oracle_eu_west_1.sealing_kms_alias
  }
}

output "github_oidc_provider_arn" {
  description = "Account-wide GitHub Actions OIDC provider ARN"
  value       = aws_iam_openid_connect_provider.github.arn
}

output "acm_dns_validation_records" {
  description = "CNAME records to add at the registrar to validate the us-east-1 ACM certificate"
  value       = module.oracle_us_east_1.acm_dns_validation_records
}

output "domain_cname_target" {
  description = "ALB DNS to point the oracle domain CNAME at (us-east-1)"
  value       = module.oracle_us_east_1.domain_cname_target
}
