# Testnet keyex fleet (Galleon 38836 -> Robinhood testnet 46630) with its own key
# root. Own VPC/SG, bucket, builder and CI role; nothing peers with or reads from
# the mainnet roots. The fleet exists only once ./eif-release.json pins both images.

locals {
  eif_release   = jsondecode(file("${path.module}/eif-release.json"))
  has_oracle    = can(local.eif_release.oracle.sha384)
  has_pontifex  = can(local.eif_release.pontifex.sha384)
  fleet_enabled = local.has_oracle && local.has_pontifex
  # Never booted (count is 0 without both pins); only satisfies the module's pin
  # validation, which the validate walk evaluates even for a zero-count module.
  no_pin = { sha384 = format("%096d", 0), pcr0 = format("%096d", 0) }
  # build-eif.sh records the baked config in each pin; only testnet builds boot here.
  pin_config = "host/eif-config/robinhood-testnet.env"

  eif_bucket_name = "${var.name_prefix}-eif"
  builder_tag     = "${var.name_prefix}-builder"
  # Must match EIF_RELEASE_SUFFIX in .github/workflows/build-eif-testnet.yml.
  host_bundle_suffix = "-testnet"

  zero_address = "0x0000000000000000000000000000000000000000"
}

module "fleet" {
  source = "../../modules/nitro-fleet"
  count  = local.fleet_enabled ? 1 : 0

  name_prefix              = var.name_prefix
  aws_region               = var.aws_region
  permissions_boundary_arn = var.permissions_boundary_arn
  vpc_cidr                 = var.vpc_cidr
  peer_cidrs               = []
  peer_asgs                = []

  ami_id              = var.ami_id
  instance_types      = concat([var.instance_type], var.instance_type_fallbacks)
  enclave_cpu_count   = var.enclave_cpu_count
  enclave_memory_mib  = var.enclave_memory_mib
  pontifex_cpu_count  = var.pontifex_cpu_count
  pontifex_memory_mib = var.pontifex_memory_mib
  enable_pontifex     = true
  asg_capacity        = var.asg_capacity
  asg_max_size        = var.asg_max_size

  eif_bucket_name    = module.eif_bucket.bucket
  eif_release_suffix = local.host_bundle_suffix
  oracle_eif         = try(local.eif_release.oracle, local.no_pin)
  pontifex_eif       = try(local.eif_release.pontifex, local.no_pin)

  log_group_name    = "/kaskad/nitro-testnet"
  alb_ingress_cidrs = var.allowed_cidrs

  # An ALB refuses a PENDING_VALIDATION cert, so HTTPS only after certificate_issued.
  domain_name      = var.certificate_issued ? var.hostname : ""
  certificate_arn  = var.certificate_issued ? aws_acm_certificate_validation.api[0].certificate_arn : ""
  edge_domain_name = ""
  edge_cert_issued = false

  oracle_registry = var.oracle_registry
  bridge_entry    = var.bridge_entry
  rh_rpcs         = var.rh_rpcs
}
