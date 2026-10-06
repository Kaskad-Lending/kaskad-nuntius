# ─── ALB for Pull API (two-AZ) ───────────────────────────────
# Without domain_name the ALB is edge-only once the edge cert is ISSUED (CloudFront
# is its only client), else HTTP on the bare ALB DNS. ACM DNS validation runs
# outside kaskad-tf (route53 forbidden).

locals {
  edge_enabled  = var.edge_domain_name != ""
  edge_attached = local.edge_enabled && var.edge_cert_issued
  https_enabled = var.domain_name != "" || local.edge_attached
  edge_only     = var.domain_name == "" && local.edge_attached
  edge_header   = "X-Kaskad-Edge"

  # Listeners that forward to the pull API; each one carries the edge guard.
  forwarding_listeners = merge(
    local.https_enabled ? { https = aws_lb_listener.https[0].arn } : {},
    var.domain_name == "" && !local.edge_only ? { http = aws_lb_listener.http_forward[0].arn } : {},
  )
  bridge_listener_arn = var.domain_name != "" || local.edge_only ? aws_lb_listener.https[0].arn : aws_lb_listener.http_forward[0].arn
}

# CloudFront's origin-facing ranges; the origin token tells our distribution apart.
data "aws_ec2_managed_prefix_list" "cloudfront_origin" {
  count = local.edge_only ? 1 : 0
  name  = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_acm_certificate" "nitro" {
  count             = var.domain_name != "" ? 1 : 0
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${var.name_prefix}-cert" }
}

# Origin cert for the edge name: CloudFront forwards the viewer Host, so it uses
# that name for SNI and certificate checks. In us-east-1 it is also the viewer cert.
resource "aws_acm_certificate" "edge" {
  count             = local.edge_enabled ? 1 : 0
  domain_name       = var.edge_domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${var.name_prefix}-edge-cert" }
}

# CloudFront sends this as an origin header; it marks requests from our distribution.
resource "random_password" "edge_origin" {
  count   = local.edge_enabled ? 1 : 0
  length  = 40
  special = false
}

resource "aws_lb" "nitro" {
  name               = "${var.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  xff_header_processing_mode = "append"
  enable_xff_client_port     = false

  tags = { Name = "${var.name_prefix}-alb" }
}

resource "aws_security_group" "alb" {
  name_prefix = "${var.name_prefix}-alb-"
  description = "ALB: HTTPS/HTTP inbound, 8080 to instances"
  vpc_id      = aws_vpc.main.id

  # Edge-only: CloudFront alone (the prefix list weighs 55 of the 60-rule quota).
  ingress {
    description     = local.edge_only ? "HTTPS from CloudFront" : "HTTPS"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    cidr_blocks     = local.edge_only ? [] : ["0.0.0.0/0"]
    prefix_list_ids = local.edge_only ? [data.aws_ec2_managed_prefix_list.cloudfront_origin[0].id] : []
  }

  dynamic "ingress" {
    for_each = local.edge_only ? [] : [80]
    content {
      description = "HTTP"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 8081
    to_port     = 8081
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = { Name = "${var.name_prefix}-alb-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_target_group" "nitro" {
  name     = "${var.name_prefix}-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/health"
    protocol            = "HTTP"
    port                = "8080"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = { Name = "${var.name_prefix}-tg" }
}

resource "aws_lb_listener" "https" {
  count             = local.https_enabled ? 1 : 0
  load_balancer_arn = aws_lb.nitro.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.domain_name != "" ? aws_acm_certificate.nitro[0].arn : aws_acm_certificate.edge[0].arn

  # Edge-only: whatever the edge guard does not forward is refused.
  default_action {
    type             = local.edge_only ? "fixed-response" : "forward"
    target_group_arn = local.edge_only ? null : aws_lb_target_group.nitro.arn

    dynamic "fixed_response" {
      for_each = local.edge_only ? [1] : []
      content {
        content_type = "application/json"
        message_body = "{\"error\":\"forbidden\"}"
        status_code  = "403"
      }
    }
  }
}

# With a domain_name the edge cert rides along on SNI.
resource "aws_lb_listener_certificate" "edge" {
  count           = local.edge_attached && var.domain_name != "" ? 1 : 0
  listener_arn    = aws_lb_listener.https[0].arn
  certificate_arn = aws_acm_certificate.edge[0].arn
}

# The edge Host is served only with the origin token, so the pull API may trust
# the X-Forwarded-For hop CloudFront appended (EDGE_HOST in pull-api.env).
resource "aws_lb_listener_rule" "edge_origin" {
  for_each     = local.edge_enabled ? local.forwarding_listeners : {}
  listener_arn = each.value
  priority     = 1

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nitro.arn
  }

  condition {
    host_header { values = [var.edge_domain_name] }
  }

  condition {
    http_header {
      http_header_name = local.edge_header
      values           = [random_password.edge_origin[0].result]
    }
  }
}

resource "aws_lb_listener_rule" "edge_bypass" {
  for_each     = local.edge_enabled ? local.forwarding_listeners : {}
  listener_arn = each.value
  priority     = 2

  action {
    type = "fixed-response"
    fixed_response {
      content_type = "application/json"
      message_body = "{\"error\":\"forbidden\"}"
      status_code  = "403"
    }
  }

  condition {
    host_header { values = [var.edge_domain_name] }
  }
}

resource "aws_lb_listener" "http_redirect" {
  count             = var.domain_name != "" ? 1 : 0
  load_balancer_arn = aws_lb.nitro.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "http_forward" {
  count             = var.domain_name == "" && !local.edge_only ? 1 : 0
  load_balancer_arn = aws_lb.nitro.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nitro.arn
  }
}

resource "aws_autoscaling_attachment" "nitro" {
  autoscaling_group_name = aws_autoscaling_group.prod.name
  lb_target_group_arn    = aws_lb_target_group.nitro.arn
}

resource "aws_lb_target_group" "bridge" {
  name     = "${var.name_prefix}-bridge"
  port     = 8081
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/bridge/ready"
    protocol            = "HTTP"
    port                = "8081"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = { Name = "${var.name_prefix}-bridge" }
}

resource "aws_autoscaling_attachment" "bridge" {
  # An oracle-only host never serves 8081; attaching it would park a
  # permanently unhealthy target in the bridge group.
  count                  = var.enable_pontifex ? 1 : 0
  autoscaling_group_name = aws_autoscaling_group.prod.name
  lb_target_group_arn    = aws_lb_target_group.bridge.arn
}

# Edge-only: the bridge sits behind the same edge guard as the pull API.
resource "aws_lb_listener_rule" "bridge_read" {
  listener_arn = local.bridge_listener_arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.bridge.arn
  }

  condition {
    http_request_method { values = ["GET"] }
  }

  condition {
    path_pattern { values = ["/bridge/health", "/bridge/attestation"] }
  }

  dynamic "condition" {
    for_each = local.edge_only ? [1] : []
    content {
      host_header { values = [var.edge_domain_name] }
    }
  }

  dynamic "condition" {
    for_each = local.edge_only ? [1] : []
    content {
      http_header {
        http_header_name = local.edge_header
        values           = [random_password.edge_origin[0].result]
      }
    }
  }
}

resource "aws_lb_listener_rule" "bridge_sign" {
  listener_arn = local.bridge_listener_arn
  priority     = 11

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.bridge.arn
  }

  condition {
    http_request_method { values = ["POST"] }
  }

  condition {
    path_pattern { values = ["/bridge/sign"] }
  }

  dynamic "condition" {
    for_each = local.edge_only ? [1] : []
    content {
      host_header { values = [var.edge_domain_name] }
    }
  }

  dynamic "condition" {
    for_each = local.edge_only ? [1] : []
    content {
      http_header {
        http_header_name = local.edge_header
        values           = [random_password.edge_origin[0].result]
      }
    }
  }
}
