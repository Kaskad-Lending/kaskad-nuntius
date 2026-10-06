# us-east-1 keyex fleet. Release artifacts (bucket, builder, CI role) live in
# this root; the builder mirrors boot artifacts into each region's own bucket.
# EIF pins: ../eif-release.json, edge (nuntius) name: ../edge.json.

locals {
  eif_release = jsondecode(file("${path.module}/../eif-release.json"))
  edge        = jsondecode(file("${path.module}/../edge.json"))
}

module "fleet" {
  source = "../../modules/nitro-fleet"

  name_prefix              = var.name_prefix
  aws_region               = var.aws_region
  permissions_boundary_arn = var.permissions_boundary_arn
  vpc_cidr                 = var.vpc_cidr
  peer_cidrs               = var.peer_cidrs
  peer_asgs                = var.peer_asgs

  ami_id              = var.ami_id
  instance_types      = concat([var.instance_type], var.instance_type_fallbacks)
  enclave_cpu_count   = var.enclave_cpu_count
  enclave_memory_mib  = var.enclave_memory_mib
  pontifex_cpu_count  = var.pontifex_cpu_count
  pontifex_memory_mib = var.pontifex_memory_mib
  enable_pontifex     = var.enable_pontifex
  asg_capacity        = var.asg_capacity
  asg_max_size        = var.asg_max_size

  eif_bucket_name    = module.eif_bucket.bucket
  eif_release_suffix = var.eif_release_suffix
  oracle_eif         = local.eif_release.oracle
  pontifex_eif       = local.eif_release.pontifex

  domain_name      = var.domain_name
  edge_domain_name = local.edge.domain
  edge_cert_issued = local.edge.certs_issued
  oracle_registry  = var.oracle_registry
  bridge_entry     = var.bridge_entry
  rh_rpcs          = var.rh_rpcs
}
