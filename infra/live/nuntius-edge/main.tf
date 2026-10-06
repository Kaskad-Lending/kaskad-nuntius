# nuntius: public pull API for signed oracle prices. US origin first; EU takes a
# request on 5xx, connect failure or timeout. keyex stays enclave key distribution.

resource "aws_cloudfront_distribution" "nuntius" {
  enabled         = true
  comment         = "nuntius oracle pull API: US primary, EU failover"
  is_ipv6_enabled = true
  http_version    = "http2and3"
  price_class     = "PriceClass_All"
  aliases         = local.edge.certs_issued ? [local.edge.domain] : []

  origin {
    origin_id           = "us"
    domain_name         = local.us.alb_dns_name
    connection_attempts = 1
    connection_timeout  = 4

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 10
      origin_keepalive_timeout = 5
    }

    custom_header {
      name  = local.us.edge_origin_header
      value = sensitive(local.us.edge_origin_token)
    }
  }

  origin {
    origin_id           = "eu"
    domain_name         = local.eu.alb_dns_name
    connection_attempts = 2
    connection_timeout  = 5

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 10
      origin_keepalive_timeout = 5
    }

    custom_header {
      name  = local.eu.edge_origin_header
      value = sensitive(local.eu.edge_origin_token)
    }
  }

  # Failover covers GET/HEAD only; a POST behavior (bridge) needs its own origin.
  origin_group {
    origin_id = "oracle"

    failover_criteria {
      status_codes = [500, 502, 503, 504]
    }

    member {
      origin_id = "us"
    }

    member {
      origin_id = "eu"
    }
  }

  default_cache_behavior {
    target_origin_id         = "oracle"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # The alias needs an ISSUED cert; until then only the *.cloudfront.net name exists.
  viewer_certificate {
    cloudfront_default_certificate = !local.edge.certs_issued
    acm_certificate_arn            = local.edge.certs_issued ? local.us.edge_certificate_arn : null
    ssl_support_method             = local.edge.certs_issued ? "sni-only" : null
    minimum_protocol_version       = local.edge.certs_issued ? "TLSv1.2_2021" : "TLSv1"
  }
}
