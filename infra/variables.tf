# ─── GitHub OIDC ──────────────────────────────────────────────

variable "front_proxy_egress" {
  description = "Egress IPs/CIDRs of the kaskad.live front proxies, trusted to attribute clients via X-Forwarded-For. Set in terraform.tfvars."
  type        = list(string)
  default     = []
}

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
