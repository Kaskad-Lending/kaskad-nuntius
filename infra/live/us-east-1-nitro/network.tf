# Fresh VPC — stands beside the live oracle, never references its VPCs.

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name_prefix}-igw" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = { Name = "${var.name_prefix}-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 2)
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}b"

  tags = { Name = "${var.name_prefix}-public-b" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "${var.name_prefix}-public-rt" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# ─── Security Groups ─────────────────────────────────────────

resource "aws_security_group" "prod" {
  name_prefix = "${var.name_prefix}-prod-"
  description = "Prod nitro: ALB inbound on 8080, HTTPS/HTTP outbound"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Pull API from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

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

  # Cross-host keyex RA-TLS handover between peers in this SG only: a successor
  # oracle sweeps peers' 8443 for the installed genesis root. The bridge fetches
  # only from its co-located oracle over loopback, so it needs no SG rule.
  ingress {
    description = "Peer RA-TLS handover (oracle 8443)"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    self        = true
  }

  egress {
    description = "Peer RA-TLS handover to same-SG peers"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    self        = true
  }

  tags = { Name = "${var.name_prefix}-prod-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "builder" {
  name_prefix = "${var.name_prefix}-builder-"
  description = "Builder: NO inbound, HTTPS/HTTP outbound for git/docker/S3"
  vpc_id      = aws_vpc.main.id

  # NO ingress — no SSH.

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

  tags = { Name = "${var.name_prefix}-builder-sg" }

  lifecycle {
    create_before_destroy = true
  }
}
