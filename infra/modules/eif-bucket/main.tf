# ─── S3 bucket for EIFs, host bundle, approvals and attestations ──

resource "aws_s3_bucket" "eif" {
  bucket = var.bucket_name

  tags = { Name = "${var.name_prefix}-eif" }
}

resource "aws_s3_bucket_versioning" "eif" {
  bucket = aws_s3_bucket.eif.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "eif" {
  bucket = aws_s3_bucket.eif.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "eif" {
  bucket = aws_s3_bucket.eif.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

locals {
  # Noncurrent-version retention per prefix; current objects never expire.
  eif_noncurrent_days = {
    "genesis/"      = 30 # rewritten every 10 min per host
    "builds/"       = 90
    "staging/"      = 90
    "oracle-probe/" = 90
  }
}

# Boot prefixes (eif/ content-addressed, host*/) and approvals/ keep full history.
resource "aws_s3_bucket_lifecycle_configuration" "eif" {
  bucket = aws_s3_bucket.eif.id

  dynamic "rule" {
    for_each = local.eif_noncurrent_days
    content {
      id     = "noncurrent-${trimsuffix(rule.key, "/")}"
      status = "Enabled"
      filter {
        prefix = rule.key
      }
      noncurrent_version_expiration {
        noncurrent_days = rule.value
      }
      expiration {
        expired_object_delete_marker = true
      }
    }
  }

  rule {
    id     = "abort-mpu"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.eif]
}
