# Static-key kaskad-tf provider. CloudFront and its viewer cert live in us-east-1.
provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "kaskad-nitro"
      ManagedBy   = "terraform"
      Environment = "prod"
    }
  }
}
