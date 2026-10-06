# eu-west-1 keyex fleet: oracle-only mirror of the US fleet. Fetches the pinned
# EIF from the us-east-1 bucket and takes the key from US peers over VPC peering.
# Edge (nuntius) name: ../edge.json.

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
  peer_cidrs               = [local.us.vpc_cidr]

  ami_id              = var.ami_id
  instance_types      = var.instance_types
  enclave_cpu_count   = var.enclave_cpu_count
  enclave_memory_mib  = var.enclave_memory_mib
  pontifex_cpu_count  = 2
  pontifex_memory_mib = 512
  enable_pontifex     = false
  asg_capacity        = var.asg_capacity
  asg_max_size        = var.asg_max_size

  eif_bucket_name    = local.us.eif_bucket
  eif_release_suffix = var.eif_release_suffix
  oracle_eif         = local.eif_release.oracle
  artifact_region    = local.us.aws_region

  peer_asgs = [{ region = local.us.aws_region, asg_name = local.us.prod_asg_name }]

  domain_name      = var.domain_name
  edge_domain_name = local.edge.domain
  edge_cert_issued = local.edge.certs_issued
  oracle_registry  = var.oracle_registry
  rh_rpcs          = var.rh_rpcs
}
