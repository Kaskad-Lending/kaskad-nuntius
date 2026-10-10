# Static-key kaskad-tf provider, no assume_role. RegionJail permits only us-east-1 / eu-west-1.
provider "aws" {
  region = var.aws_region

  # Project = kaskad-nitro is what KaskadNitroBoundary requires for SSM; the builder
  # inherits it here, fleet instances through the module's aws_default_tags read.
  default_tags {
    tags = {
      Project     = "kaskad-nitro"
      ManagedBy   = "terraform"
      Environment = "testnet"
    }
  }
}
