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

  # Local backend for initial setup.
  # Migrate to S3 once IAM is properly configured:
  #   backend "s3" {
  #     bucket = "kaskad-terraform-state"
  #     key    = "tee-oracle/terraform.tfstate"
  #     region = "us-east-1"
  #   }
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "kaskad-oracle"
      ManagedBy   = "terraform"
      Environment = "prod"
    }
  }
}

provider "aws" {
  alias  = "eu_west_1"
  region = "eu-west-1"

  default_tags {
    tags = {
      Project     = "kaskad-oracle"
      ManagedBy   = "terraform"
      Environment = "prod"
    }
  }
}

# GitHub OIDC provider — exactly one per account, shared across regions.
resource "aws_iam_openid_connect_provider" "github" {
  provider        = aws.us_east_1
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["ffffffffffffffffffffffffffffffffffffffff"]
}

module "oracle_us_east_1" {
  source    = "./modules/oracle"
  providers = { aws = aws.us_east_1 }

  name_prefix              = "kaskad-oracle"
  aws_region               = "us-east-1"
  vpc_cidr                 = "10.0.0.0/16"
  eif_bucket_name          = "kaskad-oracle-eif"
  instance_type            = "c5.xlarge"
  ami_id                   = "ami-005e66ba9068f1c2a" # standard AL2023 x86_64 (minimal lacks amazon-ssm-agent)
  enclave_cpu_count        = 2
  enclave_memory_mib       = 512
  domain_name              = "oracle.kaskad.live"
  github_org               = var.github_org
  github_repo              = var.github_repo
  github_oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
}

module "oracle_eu_west_1" {
  source    = "./modules/oracle"
  providers = { aws = aws.eu_west_1 }

  name_prefix              = "kaskad-oracle-eu-west-1"
  aws_region               = "eu-west-1"
  vpc_cidr                 = "10.1.0.0/16"
  eif_bucket_name          = "kaskad-oracle-eu-west-1-eif"
  instance_type            = "c5.xlarge"
  ami_id                   = "ami-0c13c2049f369d641" # standard AL2023 x86_64 (minimal lacks amazon-ssm-agent)
  enclave_cpu_count        = 2
  enclave_memory_mib       = 512
  asg_capacity             = 0 # infra-only until the first eu-west-1 EIF deploy populates the bucket
  domain_name              = "" # bare ALB DNS until HTTPS domain / DNS failover is decided
  github_org               = var.github_org
  github_repo              = var.github_repo
  github_oidc_provider_arn = aws_iam_openid_connect_provider.github.arn
}
