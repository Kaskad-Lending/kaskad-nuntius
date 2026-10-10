terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Same bootstrap bucket as the US root, separate key.
  backend "s3" {
    bucket       = "kaskad-terraform-state"
    key          = "kaskad-nitro-eu/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
