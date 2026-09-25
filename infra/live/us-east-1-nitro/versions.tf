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

  # Local backend for the first apply. Migrate to S3 once the state
  # bucket exists and kaskad-tf can write it.
  #   backend "s3" {
  #     bucket = "kaskad-terraform-state"
  #     key    = "kaskad-nitro-us/terraform.tfstate"
  #     region = "us-east-1"
  #   }
}
