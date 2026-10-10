# Public API cert, independent of the pins. DNS is at Namecheap: add the output
# CNAME there, wait for ISSUED, then set certificate_issued = true.

resource "aws_acm_certificate" "api" {
  domain_name       = var.hostname
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${var.name_prefix}-cert" }
}

# Only waits for ISSUED (no Route53 records), and only once asked to.
resource "aws_acm_certificate_validation" "api" {
  count           = var.certificate_issued ? 1 : 0
  certificate_arn = aws_acm_certificate.api.arn
}
