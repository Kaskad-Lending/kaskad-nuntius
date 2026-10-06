# EU values live here as defaults: *.tfvars is gitignored.

variable "name_prefix" {
  description = "Prefix for every resource name. kaskad-nitro-* only, never kaskad-oracle*."
  type        = string
  default     = "kaskad-nitro-eu"
}

variable "aws_region" {
  description = "Deploy region."
  type        = string
  default     = "eu-west-1"
}

variable "permissions_boundary_arn" {
  description = "Boundary attached to the prod role. kaskad-tf apply is denied without it."
  type        = string
  default     = "arn:aws:iam::095931689333:policy/KaskadNitroBoundary"
}

variable "vpc_cidr" {
  description = "EU fleet VPC CIDR; must not overlap the US fleet (10.20.0.0/16)."
  type        = string
  default     = "10.21.0.0/16"
}

variable "ami_id" {
  description = "AL2023 x86_64, same release as the US fleet (al2023-ami-2023.12.20260918.0)."
  type        = string
  default     = "ami-04b4d6149ad8fa801"
}

variable "instance_types" {
  description = "Oracle-only host: 2 enclave vCPUs + 2 for the parent. First is the LT default."
  type        = list(string)
  default     = ["c5.xlarge", "c5a.xlarge", "c5d.xlarge", "m5.xlarge"]
}

variable "enclave_cpu_count" {
  description = "vCPUs for the oracle enclave (CID 16)."
  type        = number
  default     = 2
}

variable "enclave_memory_mib" {
  description = "Memory (MiB) for the oracle enclave (CID 16)."
  type        = number
  default     = 1024
}

variable "asg_capacity" {
  description = "ASG desired/min size and quorum alarm floor."
  type        = number
  default     = 1
}

variable "asg_max_size" {
  description = "Headroom to scale out for a key handover before scaling in."
  type        = number
  default     = 2
}

variable "eif_bucket_name" {
  description = "This region's boot bucket; must be in the US root's eif_mirror_buckets."
  type        = string
  default     = "kaskad-nitro-eu-eif"
}

variable "eif_release_suffix" {
  description = "Host bundle prefix suffix: -mainnet boots host-mainnet/ (EIFs are content-addressed under eif/)."
  type        = string
  default     = "-mainnet"
}

variable "domain_name" {
  description = "Public API domain. Empty: edge-only once the edge cert is issued, else HTTP on the bare ALB DNS."
  type        = string
  default     = ""
}

variable "oracle_registry" {
  description = "RH oracle registry for the host configure loop."
  type        = string
  default     = "0xB4922b744cc395E05Cc962d55FA63FBab0599ec2"
}

variable "rh_rpcs" {
  description = "Comma-separated RH JSON-RPC endpoints for the host configure loop."
  type        = string
  default     = "https://rpc.mainnet.chain.robinhood.com,https://robinhood.drpc.org"
}
