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

  # Remote state in S3 (created manually or via bootstrap)
  backend "s3" {
    bucket = "kaskad-terraform-state"
    key    = "tee-oracle/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "kaskad-oracle"
      ManagedBy   = "terraform"
      Environment = var.environment
    }
  }
}
