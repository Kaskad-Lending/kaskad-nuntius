# Release artifacts and the peer fleet come from the US root.
data "terraform_remote_state" "us" {
  backend = "s3"
  config = {
    bucket = "kaskad-terraform-state"
    key    = "kaskad-nitro-us/terraform.tfstate"
    region = "us-east-1"
  }
}

locals {
  us = data.terraform_remote_state.us.outputs
}
