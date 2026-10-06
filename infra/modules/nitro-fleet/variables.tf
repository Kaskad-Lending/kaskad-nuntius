# ─── General ──────────────────────────────────────────────────

variable "name_prefix" {
  description = "Prefix for every resource name. kaskad-nitro-* only, never kaskad-oracle*."
  type        = string
}

variable "aws_region" {
  description = "Deploy region of this fleet. Must match the provider region."
  type        = string
}

variable "permissions_boundary_arn" {
  description = "Boundary attached to the prod role. kaskad-tf apply is denied without it."
  type        = string
}

# ─── Network ──────────────────────────────────────────────────

variable "vpc_cidr" {
  description = "Fleet VPC CIDR. Must not overlap any peered fleet."
  type        = string
}

variable "peer_cidrs" {
  description = "VPC CIDRs of peered fleets allowed to reach and be reached on oracle 8443."
  type        = list(string)
  default     = []
}

# ─── EC2 ──────────────────────────────────────────────────────

variable "ami_id" {
  description = "Pinned AL2023 x86_64 AMI for this region."
  type        = string
}

variable "instance_types" {
  description = "Nitro-capable types; the first is the launch-template default, the rest are ASG fallbacks."
  type        = list(string)

  validation {
    condition     = length(var.instance_types) > 0
    error_message = "instance_types needs at least one type."
  }
}

variable "enclave_cpu_count" {
  description = "vCPUs for the oracle enclave (CID 16)."
  type        = number
}

variable "enclave_memory_mib" {
  description = "Memory (MiB) for the oracle enclave (CID 16)."
  type        = number
}

variable "pontifex_cpu_count" {
  description = "vCPUs for the pontifex bridge enclave (CID 17)."
  type        = number
}

variable "pontifex_memory_mib" {
  description = "Memory (MiB) for the pontifex bridge enclave (CID 17)."
  type        = number
}

variable "enable_pontifex" {
  description = "Boot the bridge enclave beside the oracle."
  type        = bool
}

variable "asg_capacity" {
  description = "ASG desired/min size and the quorum alarm floor."
  type        = number
}

variable "asg_max_size" {
  description = "ASG max size (scale-out headroom for key handover)."
  type        = number
}

# ─── Release artifacts ────────────────────────────────────────

variable "eif_bucket_name" {
  description = "Bucket holding EIFs, host bundle, approvals and genesis attestations."
  type        = string
}

variable "eif_release_suffix" {
  description = "Host bundle prefix suffix, e.g. \"-mainnet\" boots host-mainnet/."
  type        = string

  validation {
    condition     = can(regex("^(|-[a-z0-9-]+)$", var.eif_release_suffix))
    error_message = "eif_release_suffix must be empty or start with '-' followed by lowercase alnum/dash."
  }
}

variable "oracle_eif" {
  description = "Pinned oracle image. Boot fetches eif/<sha384>.eif and refuses any sha384 or PCR0 mismatch."
  type = object({
    sha384 = string
    pcr0   = string
  })

  validation {
    condition     = can(regex("^[0-9a-f]{96}$", var.oracle_eif.sha384)) && can(regex("^[0-9a-f]{96}$", var.oracle_eif.pcr0))
    error_message = "oracle_eif.sha384 and oracle_eif.pcr0 must be 96 lowercase hex chars."
  }
}

variable "pontifex_eif" {
  description = "Pinned bridge image, same contract as oracle_eif. Required when enable_pontifex."
  type = object({
    sha384 = string
    pcr0   = string
  })
  default = null

  validation {
    condition = var.pontifex_eif == null || (
      can(regex("^[0-9a-f]{96}$", var.pontifex_eif.sha384)) && can(regex("^[0-9a-f]{96}$", var.pontifex_eif.pcr0))
    )
    error_message = "pontifex_eif.sha384 and pontifex_eif.pcr0 must be 96 lowercase hex chars."
  }
}

variable "artifact_region" {
  description = "Region of the EIF bucket. Null = aws_region."
  type        = string
  default     = null
}

# ─── Cross-region keyex peers ─────────────────────────────────

variable "peer_asgs" {
  description = "Other-region fleet ASGs whose oracles are RA-TLS handover peers."
  type = list(object({
    region   = string
    asg_name = string
  }))
  default = []
}

variable "enclave_debug_mode" {
  description = "Debug enclaves get a console but attest zero PCRs, so peers refuse handover. Never in prod."
  type        = bool
  default     = false
}

# ─── ALB / DNS ────────────────────────────────────────────────

variable "domain_name" {
  description = "API domain. Empty = HTTP on the bare ALB DNS, no ACM."
  type        = string
  default     = ""
}

variable "edge_domain_name" {
  description = "Public oracle name served through CloudFront (nuntius). Empty = no edge."
  type        = string
  default     = ""
}

variable "edge_cert_issued" {
  description = "True once the edge ACM cert is ISSUED (validated outside kaskad-tf); attaches it to HTTPS."
  type        = bool
  default     = false
}

# ─── Host-plane hints (untrusted) ─────────────────────────────

variable "oracle_registry" {
  description = "RH oracle registry for the host configure loop. Empty idles the loop."
  type        = string
  default     = ""
}

variable "bridge_entry" {
  description = "RH KskdEntry for the bridge half of the configure loop. Empty idles it."
  type        = string
  default     = ""
}

variable "rh_rpcs" {
  description = "Comma-separated RH JSON-RPC endpoints for the host configure loop."
  type        = string
  default     = ""
}
