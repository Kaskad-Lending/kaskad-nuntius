# ─── VPC ──────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.project_name}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.project_name}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1) # 10.0.1.0/24
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = { Name = "${var.project_name}-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ─── Security Groups ─────────────────────────────────────────

resource "aws_security_group" "prod" {
  name_prefix = "${var.project_name}-prod-"
  description = "Prod oracle: NO inbound, HTTPS outbound only"
  vpc_id      = aws_vpc.main.id

  # NO ingress rules — zero inbound ports, no SSH

  egress {
    description = "HTTPS (RPC, APIs)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP (some APIs)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-prod-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "builder" {
  name_prefix = "${var.project_name}-builder-"
  description = "Builder: NO inbound, HTTPS outbound for git/docker/S3"
  vpc_id      = aws_vpc.main.id

  # NO ingress — no SSH

  egress {
    description = "HTTPS (git, Docker Hub, S3)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.project_name}-builder-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# ─── VPC Endpoints (SSM for debugging without SSH) ────────────

resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public.id]
  security_group_ids  = [aws_security_group.prod.id]
  private_dns_enabled = true

  tags = { Name = "${var.project_name}-ssm-endpoint" }
}

resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.public.id]
  security_group_ids  = [aws_security_group.prod.id]
  private_dns_enabled = true

  tags = { Name = "${var.project_name}-ssm-messages-endpoint" }
}
