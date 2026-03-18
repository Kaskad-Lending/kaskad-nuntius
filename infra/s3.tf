# ─── S3 Bucket for EIF Artifacts ──────────────────────────────

resource "aws_s3_bucket" "eif" {
  bucket = var.eif_bucket_name

  tags = { Name = "${var.project_name}-eif" }
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
