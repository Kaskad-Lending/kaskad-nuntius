# Origins, their tokens and the viewer cert come from the fleet roots.
data "terraform_remote_state" "us" {
  backend = "s3"
  config = {
    bucket = "kaskad-terraform-state"
    key    = "kaskad-nitro-us/terraform.tfstate"
    region = "us-east-1"
  }
}

data "terraform_remote_state" "eu" {
  backend = "s3"
  config = {
    bucket = "kaskad-terraform-state"
    key    = "kaskad-nitro-eu/terraform.tfstate"
    region = "us-east-1"
  }
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

# Forwards the viewer Host: the origin ALBs match it and present the edge cert by SNI.
data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewer"
}

locals {
  edge = jsondecode(file("${path.module}/../edge.json"))
  us   = data.terraform_remote_state.us.outputs
  eu   = data.terraform_remote_state.eu.outputs
}
