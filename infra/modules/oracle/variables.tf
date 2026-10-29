# ─── General ──────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for all resource names in this region's deployment"
  type        = string
}

variable "aws_region" {
  description = "AWS region this module instance deploys into"
  type        = string
  default     = "us-east-1"
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

variable "ami_id" {
  description = "Pinned standard AL2023 x86_64 AMI for this region. Pin explicitly: most_recent drifts non-deterministically and AMI IDs are per-region. Standard, not minimal (minimal lacks amazon-ssm-agent)."
  type        = string
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

variable "asg_capacity" {
  description = "Prod ASG desired/min size. 0 stands up a region's infra before its first EIF deploy; 1 once the EIF bucket is populated."
  type        = number
  default     = 1
}

# ─── S3 ───────────────────────────────────────────────────────

variable "eif_bucket_name" {
  description = "S3 bucket for EIF artifacts"
  type        = string
  default     = "kaskad-oracle-eif"
}

variable "trusted_proxies" {
  description = <<-EOT
    Egress addresses (IP or CIDR) of front proxies allowed to attribute a
    client via X-Forwarded-For. The ALB is public, so every XFF entry left of
    the one the ALB appends is caller-authored; pull_api.py walks the chain
    right to left past these and keys the rate limiter on the first entry
    that remains. Empty leaves it keying on the leftmost entry, which any
    caller can forge.
  EOT
  type        = list(string)
  default     = []
}

# ─── ALB / DNS ────────────────────────────────────────────────

variable "domain_name" {
  description = "Domain name for the oracle API. Set empty to skip ACM/HTTPS and stay on bare ALB DNS."
  type        = string
  default     = "oracle.kaskad.live"
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

variable "github_oidc_provider_arn" {
  description = "ARN of the account-wide GitHub Actions OIDC provider (created in the root module)"
  type        = string
}
