terraform {
  # use_lockfile needs 1.10.
  required_version = ">= 1.10"

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

  # Same bootstrap state bucket as the mainnet roots, separate key.
  backend "s3" {
    bucket       = "kaskad-terraform-state"
    key          = "kaskad-nitro-testnet/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
