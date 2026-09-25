# Static-key provider — kaskad-tf IAM user, no assume_role. RegionJail
# permits only us-east-1 / eu-west-1; this root is pinned to us-east-1.
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "kaskad-nitro"
      ManagedBy   = "terraform"
      Environment = "prod"
    }
  }
}
