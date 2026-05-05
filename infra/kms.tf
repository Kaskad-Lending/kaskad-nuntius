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

# ═══════════════════════════════════════════════════════════════
# KMS — Enclave Key Sealing (survive spot reclaim / restart)
# ═══════════════════════════════════════════════════════════════
#
# Symmetric KMS key that wraps the enclave's secp256k1 signing key.
# The enclave generates the signing key on first boot, encrypts it
# with this key (kms:Encrypt — host-side OK, public key wrap),
# uploads the ciphertext to S3.
#
# On restart: enclave fetches the ciphertext, builds a Nitro
# attestation document with an ephemeral RSA pubkey in user_data,
# calls kms:Decrypt with `Recipient: AttestationDocument`. KMS
# verifies the attestation against `kms:RecipientAttestation:PCR0`
# in the key policy and returns the plaintext encrypted with the
# attestation's ephemeral pubkey. The host never sees the plaintext.
#
# Without this, every spot reclaim / instance refresh regenerates
# the enclave key, which forces a full Mock-verifier + Oracle +
# aggregators redeploy on Galleon.

variable "sealing_allowed_pcr0" {
  description = "List of PCR0 measurements (hex, 96 chars) the sealing KMS key will decrypt for. CI publishes a new PCR0 on each EIF build; operator updates this list."
  type        = list(string)
  default     = []
}

resource "aws_kms_key" "sealing" {
  description              = "Kaskad Oracle enclave signing-key sealing key (PCR0-gated decrypt)"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  deletion_window_in_days  = 30
  enable_key_rotation      = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        # Account root — admin / break-glass.
        {
          Sid       = "RootAccountFullAccess"
          Effect    = "Allow"
          Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
          Action    = "kms:*"
          Resource  = "*"
        },
        # Prod EC2 role: kms:Encrypt unconditional (host-side OK,
        # the plaintext lives only inside the enclave anyway).
        {
          Sid       = "ProdEncryptOnFirstBoot"
          Effect    = "Allow"
          Principal = { AWS = aws_iam_role.prod.arn }
          Action    = ["kms:Encrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
          Resource  = "*"
        },
      ],
      # kms:Decrypt only with a Nitro attestation that resolves to
      # one of the allowed PCR0 measurements.
      length(var.sealing_allowed_pcr0) > 0 ? [
        {
          Sid       = "ProdDecryptWithAttestation"
          Effect    = "Allow"
          Principal = { AWS = aws_iam_role.prod.arn }
          Action    = "kms:Decrypt"
          Resource  = "*"
          Condition = {
            "ForAnyValue:StringEqualsIgnoreCase" = {
              "kms:RecipientAttestation:PCR0" = var.sealing_allowed_pcr0
            }
          }
        }
      ] : []
    )
  })

  tags = {
    Name = "${var.project_name}-key-sealing"
  }
}

resource "aws_kms_alias" "sealing" {
  name          = "alias/${var.project_name}-sealing"
  target_key_id = aws_kms_key.sealing.id
}

output "sealing_kms_key_arn" {
  description = "ARN of the enclave-key sealing KMS key"
  value       = aws_kms_key.sealing.arn
}

output "sealing_kms_alias" {
  description = "Alias of the sealing KMS key"
  value       = aws_kms_alias.sealing.name
}
