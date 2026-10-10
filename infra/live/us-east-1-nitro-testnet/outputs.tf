output "aws_region" {
  value = var.aws_region
}

output "eif_bucket" {
  value = module.eif_bucket.bucket
}

output "github_ci_role_arn" {
  description = "Role build-eif-testnet.yml assumes; trusted only for eif-testnet-v* tag refs."
  value       = aws_iam_role.github_ci.arn
}

output "builder_tag" {
  description = "Name tag CI finds and drives the builder by."
  value       = local.builder_tag
}

output "builder_instance_id" {
  value = aws_instance.builder.id
}

output "certificate_arn" {
  value = aws_acm_certificate.api.arn
}

output "certificate_validation_records" {
  description = "CNAMEs to add at Namecheap; set certificate_issued once ACM shows ISSUED."
  value = [
    for opt in aws_acm_certificate.api.domain_validation_options : {
      cname_name  = opt.resource_record_name
      cname_value = opt.resource_record_value
      type        = opt.resource_record_type
    }
  ]
}

output "fleet_enabled" {
  description = "True once eif-release.json pins both images."
  value       = local.fleet_enabled

  # Dropping one pin from a live fleet would destroy it, and with it the key root.
  precondition {
    condition     = local.has_oracle == local.has_pontifex
    error_message = "eif-release.json must pin both oracle and pontifex, or neither."
  }

  # Catches pins pasted from ../eif-release.json (robinhood-mainnet.env).
  precondition {
    condition     = alltrue([for k in ["oracle", "pontifex"] : !can(local.eif_release[k].sha384) || try(local.eif_release[k].config, "") == local.pin_config])
    error_message = "Each eif-release.json pin must carry config = host/eif-config/robinhood-testnet.env."
  }

  # The enclaves refuse any registry/entry but their baked one, so a placeholder fleet never configures.
  precondition {
    condition     = !local.fleet_enabled || (var.oracle_registry != local.zero_address && var.bridge_entry != local.zero_address)
    error_message = "Set oracle_registry and bridge_entry to the baked addresses before pinning."
  }
}

output "alb_dns_name" {
  description = "Fleet ALB DNS, null until both pins land. The hostname CNAME at Namecheap points here."
  value       = one(module.fleet[*].alb_dns_name)
}

output "prod_asg_name" {
  description = "Fleet ASG, null until both pins land. Rolls scale it out and back in by hand."
  value       = one(module.fleet[*].asg_name)
}
