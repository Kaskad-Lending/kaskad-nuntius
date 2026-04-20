# ─── General ──────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "project_name" {
  description = "Project name prefix for resources"
  type        = string
  default     = "kaskad-oracle"
}

# ─── Network ──────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

# ─── EC2 ──────────────────────────────────────────────────────

variable "instance_type" {
  description = "EC2 instance type (must support Nitro Enclaves, min c5.xlarge)"
  type        = string
  default     = "c5.xlarge"
}

variable "enclave_cpu_count" {
  description = "vCPUs allocated to the enclave"
  type        = number
  default     = 2
}

variable "enclave_memory_mib" {
  description = "Memory in MiB allocated to the enclave"
  type        = number
  default     = 512
}

# ─── S3 ───────────────────────────────────────────────────────

variable "eif_bucket_name" {
  description = "S3 bucket for EIF artifacts"
  type        = string
  default     = "kaskad-oracle-eif"
}

# ─── Oracle Config ────────────────────────────────────────────

variable "rpc_url" {
  description = "Blockchain RPC URL for the oracle"
  type        = string
  sensitive   = true
}

variable "oracle_contract" {
  description = "Address of the KaskadPriceOracle contract"
  type        = string
}

variable "chain_id" {
  description = "Chain ID for transaction signing"
  type        = number
  default     = 1
}

# ─── GitHub OIDC ──────────────────────────────────────────────

variable "github_org" {
  description = "GitHub organization"
  type        = string
  default     = "Kaskad-Lending"
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "kaskad-nuntius"
}
