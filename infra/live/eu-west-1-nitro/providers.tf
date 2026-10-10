# Static-key kaskad-tf provider, no assume_role. RegionJail permits only us-east-1 / eu-west-1.
locals {
  default_tags = {
    Project     = "kaskad-nitro"
    ManagedBy   = "terraform"
    Environment = "prod"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.default_tags
  }
}

# US side of the peering: accepter + return route on the US fleet route table.
provider "aws" {
  alias  = "us"
  region = "us-east-1"

  default_tags {
    tags = local.default_tags
  }
}
