terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }

  # Bucket is bootstrapped outside terraform (versioned, SSE-S3, public access blocked).
  backend "s3" {
    bucket       = "kaskad-terraform-state"
    key          = "kaskad-nitro-us/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
