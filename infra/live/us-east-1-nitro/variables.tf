# ─── General ──────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for every resource name in this stack. Never kaskad-oracle*."
  type        = string
  default     = "kaskad-nitro-us"
}

variable "aws_region" {
  description = "Deploy region. RegionJail allows only us-east-1 / eu-west-1."
  type        = string
  default     = "us-east-1"
}

variable "permissions_boundary_arn" {
  description = "Boundary attached to every IAM role. Required — kaskad-tf apply is denied without it."
  type        = string
  default     = "arn:aws:iam::095931689333:policy/KaskadNitroBoundary"
}

# ─── Network ──────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "VPC CIDR for the new stack. Fresh VPC — never the live oracle VPCs."
  type        = string
  default     = "10.20.0.0/16"
}

# ─── EC2 ──────────────────────────────────────────────────────

variable "instance_type" {
  description = "Instance type — Nitro-capable, >=6 vCPU: two enclaves take 4 (oracle 2 + bridge 2) and Nitro must leave >=2 for the parent."
  type        = string
  default     = "c5.2xlarge"
}

variable "ami_id" {
  description = "Pinned AL2023 x86_64 AMI (standard, not minimal). Per-region — pin explicitly."
  type        = string
}

variable "enclave_cpu_count" {
  description = "vCPUs for the oracle enclave (CID 16, price + keyex genesis)."
  type        = number
  default     = 2
}

variable "enclave_memory_mib" {
  description = "Memory (MiB) for the oracle enclave (CID 16). Full price loop + rustls needs headroom."
  type        = number
  default     = 1024
}

variable "pontifex_cpu_count" {
  description = "vCPUs for the pontifex bridge enclave (CID 17). Light, but Nitro requires an even count on hyperthreaded hosts, so 2 (one full core)."
  type        = number
  default     = 2
}

variable "pontifex_memory_mib" {
  description = "Memory (MiB) for the pontifex bridge enclave (CID 17)."
  type        = number
  default     = 512
}

variable "asg_capacity" {
  description = "Prod ASG desired/min size. Two-AZ keyex quorum floor."
  type        = number
  default     = 2
}

variable "asg_max_size" {
  description = "Prod ASG max size (headroom for instance refresh)."
  type        = number
  default     = 4
}

variable "enable_sealing" {
  description = "KMS key-sealing. Off for keyex — custody is the enclave fleet, not KMS."
  type        = bool
  default     = false
}

# ─── S3 ───────────────────────────────────────────────────────

variable "eif_bucket_name" {
  description = "S3 bucket for EIF artifacts."
  type        = string
  default     = "kaskad-nitro-us-eif"
}

# ─── ALB / DNS ────────────────────────────────────────────────

variable "domain_name" {
  description = "API domain. Empty = bare ALB DNS, no ACM/HTTPS (route53 forbidden here; ACM DNS-validation runs outside kaskad-tf)."
  type        = string
  default     = ""
}

# ─── Host-plane hints (untrusted) ─────────────────────────────
# Passed to pontifex_host.py / pull_api.py via user-data. The enclave bakes its
# own trust-critical addresses into PCR0 — these are convenience hints only, so
# they stay empty until go-live and never gate correctness.

variable "oracle_registry" {
  description = "RH KaskadPriceOracle address for the pontifex host config loop. Empty until go-live."
  type        = string
  default     = ""
}

variable "bridge_entry" {
  description = "RH KskdEntry address for the pontifex host config loop. Empty until go-live."
  type        = string
  default     = ""
}

variable "rh_rpcs" {
  description = "Comma-separated RH JSON-RPC endpoints for the pontifex host. Empty until go-live."
  type        = string
  default     = ""
}

# ─── GitHub OIDC ──────────────────────────────────────────────

variable "github_org" {
  description = "GitHub organization."
  type        = string
  default     = "Kaskad-Lending"
}

variable "github_repo" {
  description = "GitHub repository name."
  type        = string
  default     = "kaskad-nuntius"
}

variable "oidc_provider_arn" {
  description = "Account-wide GitHub OIDC provider ARN. Reused — this root never creates one."
  type        = string
  default     = "arn:aws:iam::095931689333:oidc-provider/token.actions.githubusercontent.com"
}
