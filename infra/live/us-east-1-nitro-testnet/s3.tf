# Testnet release + boot bucket: EIFs, host bundle, approvals/ and attestations. No mirrors.
module "eif_bucket" {
  source      = "../../modules/eif-bucket"
  bucket_name = local.eif_bucket_name
  name_prefix = var.name_prefix
}
