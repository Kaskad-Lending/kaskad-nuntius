# Release bucket: CI builds and staging land here; the builder mirrors boot
# artifacts (eif/, host*/) into each var.eif_mirror_buckets entry.
module "eif_bucket" {
  source      = "../../modules/eif-bucket"
  bucket_name = var.eif_bucket_name
  name_prefix = var.name_prefix
}
