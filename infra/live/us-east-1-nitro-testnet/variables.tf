# ─── General ──────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for every resource name. kaskad-nitro-* only: kaskad-tf may create IAM only under it."
  type        = string
  default     = "kaskad-nitro-testnet"

  validation {
    condition     = can(regex("^kaskad-nitro-[a-z0-9-]+$", var.name_prefix))
    error_message = "name_prefix must start with kaskad-nitro-."
  }
}

variable "aws_region" {
  description = "Deploy region. RegionJail allows only us-east-1 / eu-west-1."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = contains(["us-east-1", "eu-west-1"], var.aws_region)
    error_message = "aws_region must be us-east-1 or eu-west-1."
  }
}

variable "permissions_boundary_arn" {
  description = "Boundary on every IAM role; kaskad-tf apply is denied without it."
  type        = string
  default     = "arn:aws:iam::095931689333:policy/KaskadNitroBoundary"
}

# ─── Network ──────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "Fleet VPC CIDR. Unpeered: RA-TLS 8443 is SG-scoped, so no mainnet oracle is ever a peer."
  type        = string
  default     = "10.22.0.0/16"
}

variable "builder_vpc_cidr" {
  description = "Builder-only VPC CIDR. The fleet VPC is pin-gated, the builder must exist before the first pin."
  type        = string
  default     = "10.23.0.0/16"
}

variable "allowed_cidrs" {
  description = "IPv4 CIDRs allowed on ALB 443/80, e.g. the bridge relayer host."
  type        = list(string)

  validation {
    condition     = length(var.allowed_cidrs) > 0 && alltrue([for c in var.allowed_cidrs : can(cidrnetmask(c))])
    error_message = "allowed_cidrs needs at least one IPv4 CIDR."
  }
}

# ─── EC2 ──────────────────────────────────────────────────────

variable "ami_id" {
  description = "Pinned AL2023 x86_64 AMI (standard, not minimal) in aws_region; same release as the US fleet."
  type        = string
}

variable "instance_type" {
  description = "Nitro-capable, >=6 vCPU: oracle 2 + bridge 2 enclave vCPUs and >=2 for the parent. Also the builder type."
  type        = string
  default     = "c5.2xlarge"
}

variable "instance_type_fallbacks" {
  description = "ASG fallback types when instance_type has no capacity. Same vCPU class."
  type        = list(string)
  default     = ["c5a.2xlarge", "c5d.2xlarge", "m5.2xlarge"]
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

variable "pontifex_cpu_count" {
  description = "vCPUs for the bridge enclave (CID 17); even, a full core on hyperthreaded hosts."
  type        = number
  default     = 2
}

variable "pontifex_memory_mib" {
  description = "Memory (MiB) for the bridge enclave (CID 17)."
  type        = number
  default     = 512
}

variable "asg_capacity" {
  description = "ASG desired/min size and the quorum alarm floor."
  type        = number
  default     = 1
}

variable "asg_max_size" {
  description = "ASG max size: room to scale out for a key handover, then back in."
  type        = number
  default     = 2
}

# ─── ALB / DNS ────────────────────────────────────────────────

variable "hostname" {
  description = "Public API name. DNS is at Namecheap: the cert CNAME and the hostname CNAME to the ALB are added there."
  type        = string
  default     = "nuntius-testnet.kaskad.live"
}

variable "certificate_issued" {
  description = "True once ACM shows the hostname cert ISSUED; attaches it to HTTPS. False serves HTTP on the bare ALB DNS."
  type        = bool
  default     = false
}

# ─── Host-plane hints (untrusted) ─────────────────────────────
# The enclaves accept only their baked addresses (host/eif-config/robinhood-testnet.env);
# anything else is refused, so a wrong hint stalls the fleet but cannot redirect it.

variable "oracle_registry" {
  description = "RH 46630 KaskadPriceOracle registry; must equal KEYEX_ORACLE_REGISTRY baked in the pinned oracle EIF."
  type        = string

  validation {
    condition     = can(regex("^0x[0-9a-fA-F]{40}$", var.oracle_registry))
    error_message = "oracle_registry must be a 0x-prefixed 20-byte address."
  }
}

variable "bridge_entry" {
  description = "RH 46630 KskdEntry; must equal PONTIFEX_ENTRY baked in the pinned bridge EIF, else the bridge is never configured."
  type        = string

  validation {
    condition     = can(regex("^0x[0-9a-fA-F]{40}$", var.bridge_entry))
    error_message = "bridge_entry must be a 0x-prefixed 20-byte address."
  }
}

variable "rh_rpcs" {
  description = "Comma-separated RH 46630 JSON-RPC endpoints, failover order. The bridge uses them and refuses non-https."
  type        = string
  default     = "https://robinhood-testnet.drpc.org,https://rpc.testnet.chain.robinhood.com"

  validation {
    condition     = alltrue([for u in split(",", var.rh_rpcs) : startswith(trimspace(u), "https://")])
    error_message = "rh_rpcs must be one or more comma-separated https:// URLs."
  }
}
