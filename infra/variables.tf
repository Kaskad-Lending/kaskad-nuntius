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
