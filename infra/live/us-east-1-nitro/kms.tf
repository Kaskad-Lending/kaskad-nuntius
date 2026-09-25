# EIF release signing key — separate kaskad-nitro key. CI signs the
# EIF SHA-384 digest + PCR0 manifest; prod verifies at boot before
# run-enclave. No sealing key: keyex custody is the enclave fleet.

resource "aws_kms_key" "release" {
  description              = "kaskad-nitro EIF release signing key"
  customer_master_key_spec = "ECC_NIST_P384"
  key_usage                = "SIGN_VERIFY"
  deletion_window_in_days  = 30
  enable_key_rotation      = false # Asymmetric keys do not auto-rotate.

  tags = { Name = "${var.name_prefix}-release-signing" }
}

resource "aws_kms_alias" "release" {
  name          = "alias/${var.name_prefix}-release"
  target_key_id = aws_kms_key.release.id
}

# ─── IAM grants ───────────────────────────────────────────────

resource "aws_iam_role_policy" "builder_kms_sign" {
  name = "${var.name_prefix}-builder-kms-sign"
  role = aws_iam_role.builder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SignReleaseArtifacts"
      Effect   = "Allow"
      Action   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
      Resource = [aws_kms_key.release.arn]
    }]
  })
}

resource "aws_iam_role_policy" "prod_kms_verify" {
  name = "${var.name_prefix}-prod-kms-verify"
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

resource "aws_iam_role_policy" "github_ci_kms_sign" {
  name = "${var.name_prefix}-github-ci-kms-sign"
  role = aws_iam_role.github_ci.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "SignReleaseArtifacts"
      Effect   = "Allow"
      Action   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
      Resource = [aws_kms_key.release.arn]
    }]
  })
}
