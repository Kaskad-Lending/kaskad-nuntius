# Retired release key: nothing signs or verifies with it. Kept until deletion is approved.

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
