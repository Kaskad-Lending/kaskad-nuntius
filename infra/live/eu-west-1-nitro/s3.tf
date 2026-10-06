# This region's boot bucket. The release mirrors eif/ and host*/ here; owner-signed
# approvals/ go to every regional bucket; hosts publish genesis/ and diag/ here.
module "eif_bucket" {
  source      = "../../modules/eif-bucket"
  bucket_name = var.eif_bucket_name
  name_prefix = var.name_prefix
}
