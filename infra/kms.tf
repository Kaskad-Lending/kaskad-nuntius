# ═══════════════════════════════════════════════════════════════
# KMS — Release Signing Key for EIF Integrity Pin
# ═══════════════════════════════════════════════════════════════
#
# CI builder signs the EIF SHA-384 digest and the PCR0 manifest with
# this key after each successful build. Prod hosts fetch the public
# key once at boot and verify both signatures locally with `openssl
# dgst -verify` before invoking `nitro-cli run-enclave` — closing the
# audit C-5/C-6 gap (S3 compromise replaces `latest.eif` with a
# sabotaged image).
#
# Key spec: ECC_NIST_P384 / ECDSA_SHA_384 — matches our SHA-384 digest
# pipeline and is widely supported by openssl + AWS KMS.

resource "aws_kms_key" "release" {
  description              = "Kaskad Oracle EIF release signing key"
  customer_master_key_spec = "ECC_NIST_P384"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  enable_key_rotation      = false # Asymmetric keys do not support automatic rotation.

  tags = {
    Name = "${var.project_name}-release-signing"
  }
}

resource "aws_kms_alias" "release" {
  name          = "alias/${var.project_name}-release"
  target_key_id = aws_kms_key.release.id
}

# ─── IAM grants ───────────────────────────────────────────────

# Builder EC2 (CI runs `aws kms sign` from there) — needs Sign + GetPublicKey.
resource "aws_iam_role_policy" "builder_kms_sign" {
  name = "${var.project_name}-builder-kms-sign"
  role = aws_iam_role.builder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SignReleaseArtifacts"
      Effect = "Allow"
      Action = [
        "kms:Sign",
        "kms:GetPublicKey",
        "kms:DescribeKey"
      ]
      Resource = [aws_kms_key.release.arn]
    }]
  })
}

# Prod EC2 (verifies signatures at boot) — public key only, no Sign.
resource "aws_iam_role_policy" "prod_kms_verify" {
  name = "${var.project_name}-prod-kms-verify"
  role = aws_iam_role.prod.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "FetchReleasePublicKey"
      Effect   = "Allow"
      Action   = ["kms:GetPublicKey", "kms:DescribeKey"]
      Resource = [aws_kms_key.release.arn]
    }]
  })
}

# GitHub OIDC role (CI orchestrator) — needs Sign too if signing happens
# directly from the GH runner instead of the builder. Today signing happens
# on the builder via SSM; this grant is reserved for a future CI move.
resource "aws_iam_role_policy" "github_ci_kms_sign" {
  name = "${var.project_name}-github-ci-kms-sign"
  role = aws_iam_role.github_ci.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "SignReleaseArtifacts"
      Effect = "Allow"
      Action = [
        "kms:Sign",
        "kms:GetPublicKey",
        "kms:DescribeKey"
      ]
      Resource = [aws_kms_key.release.arn]
    }]
  })
}

output "release_kms_key_arn" {
  description = "ARN of the EIF release signing KMS key"
  value       = aws_kms_key.release.arn
}

output "release_kms_alias" {
  description = "Alias of the release signing KMS key (used by aws kms sign / verify)"
  value       = aws_kms_alias.release.name
}
