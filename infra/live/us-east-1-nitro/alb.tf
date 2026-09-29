# ─── ALB for Pull API (two-AZ) ───────────────────────────────
# domain_name="" here: no ACM/HTTPS, API served on bare ALB DNS.
# ACM DNS-validation runs outside kaskad-tf (route53 forbidden).

resource "aws_acm_certificate" "nitro" {
  count             = var.domain_name != "" ? 1 : 0
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${var.name_prefix}-cert" }
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

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
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
  count             = var.domain_name != "" ? 1 : 0
  load_balancer_arn = aws_lb.nitro.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.nitro[0].arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nitro.arn
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
  count             = var.domain_name != "" ? 0 : 1
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
  autoscaling_group_name = aws_autoscaling_group.prod.name
  lb_target_group_arn    = aws_lb_target_group.bridge.arn
}

resource "aws_lb_listener_rule" "bridge_read" {
  listener_arn = var.domain_name != "" ? aws_lb_listener.https[0].arn : aws_lb_listener.http_forward[0].arn
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
}

resource "aws_lb_listener_rule" "bridge_sign" {
  listener_arn = var.domain_name != "" ? aws_lb_listener.https[0].arn : aws_lb_listener.http_forward[0].arn
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
}
