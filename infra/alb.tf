# ─── ALB for Pull API (HTTPS → port 8080) ────────────────────

variable "domain_name" {
  description = "Domain name for the oracle API (e.g. oracle.kaskad.io)"
  type        = string
  default     = ""
}

# ACM Certificate (DNS validation)
resource "aws_acm_certificate" "oracle" {
  count             = var.domain_name != "" ? 1 : 0
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = "${var.project_name}-cert" }
}

# ALB
resource "aws_lb" "oracle" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public.id, aws_subnet.public_b.id]

  tags = { Name = "${var.project_name}-alb" }
}

# Second subnet in different AZ (required for ALB)
resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 2) # 10.0.2.0/24
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}b"

  tags = { Name = "${var.project_name}-public-b" }
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# ALB Security Group
resource "aws_security_group" "alb" {
  name_prefix = "${var.project_name}-alb-"
  description = "ALB: HTTPS inbound, 8080 to instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP (redirect to HTTPS)"
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

  tags = { Name = "${var.project_name}-alb-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# Target Group
resource "aws_lb_target_group" "oracle" {
  name     = "${var.project_name}-tg"
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

  tags = { Name = "${var.project_name}-tg" }
}

# HTTPS Listener (when certificate is available)
resource "aws_lb_listener" "https" {
  count             = var.domain_name != "" ? 1 : 0
  load_balancer_arn = aws_lb.oracle.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.oracle[0].arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.oracle.arn
  }
}

# HTTP Listener — behaviour depends on whether a domain (and therefore
# an HTTPS listener) is attached. With cert: 301-redirect to HTTPS so
# clients upgrade transparently. Without cert: passthrough so the API
# is reachable on the bare ALB DNS until DNS validation completes.
resource "aws_lb_listener" "http_redirect" {
  count             = var.domain_name != "" ? 1 : 0
  load_balancer_arn = aws_lb.oracle.arn
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
  load_balancer_arn = aws_lb.oracle.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.oracle.arn
  }
}

# Attach ASG to target group
resource "aws_autoscaling_attachment" "oracle" {
  autoscaling_group_name = aws_autoscaling_group.prod.name
  lb_target_group_arn    = aws_lb_target_group.oracle.arn
}

# Output ALB DNS
output "alb_dns_name" {
  description = "ALB DNS name — use this to access the pull API directly, or as the CNAME target for the oracle domain"
  value       = aws_lb.oracle.dns_name
}

# ─── External DNS (Namecheap etc.) bootstrap ──────────────────
# If `var.domain_name` is set, Terraform creates the ACM cert with
# DNS-validation. The certificate stays in `PENDING_VALIDATION` until
# the operator adds the CNAME records below at the registrar. After
# DNS propagates (~minutes for Namecheap), `terraform apply` again to
# unblock the validation, attach HTTPS listener, and flip HTTP to
# 301-redirect.
output "acm_dns_validation_records" {
  description = "CNAME records to add at the registrar (e.g. Namecheap) to validate the ACM certificate. After adding, run `terraform apply` again to finish issuance."
  value = var.domain_name == "" ? [] : [
    for opt in aws_acm_certificate.oracle[0].domain_validation_options : {
      cname_name  = opt.resource_record_name
      cname_value = opt.resource_record_value
      type        = opt.resource_record_type
    }
  ]
}

output "domain_cname_target" {
  description = "Where to point the domain at your registrar — add a CNAME (or ALIAS, if supported) from var.domain_name to this ALB DNS."
  value       = var.domain_name == "" ? null : aws_lb.oracle.dns_name
}
