# Per-region fleet VPC — never references the Igra oracle VPCs.

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

# Routes are standalone (route omitted = ignored) so peering roots can add theirs.
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name_prefix}-public-rt" }
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
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

  ingress {
    description     = "Bridge API from ALB"
    from_port       = 8081
    to_port         = 8081
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "Galleon HTTPS JSON-RPC"
    from_port   = 8545
    to_port     = 8545
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
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

  # Cross-host keyex RA-TLS handover: a successor oracle sweeps peers' 8443.
  # The bridge fetches from its co-located oracle over loopback, no SG rule.
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

  # Cross-region peers over VPC peering; SG references do not cross regions.
  dynamic "ingress" {
    for_each = length(var.peer_cidrs) > 0 ? [var.peer_cidrs] : []
    content {
      description = "Cross-region peer RA-TLS handover (oracle 8443)"
      from_port   = 8443
      to_port     = 8443
      protocol    = "tcp"
      cidr_blocks = ingress.value
    }
  }

  dynamic "egress" {
    for_each = length(var.peer_cidrs) > 0 ? [var.peer_cidrs] : []
    content {
      description = "Cross-region peer RA-TLS handover (oracle 8443)"
      from_port   = 8443
      to_port     = 8443
      protocol    = "tcp"
      cidr_blocks = egress.value
    }
  }

  tags = { Name = "${var.name_prefix}-prod-sg" }

  lifecycle {
    create_before_destroy = true
  }
}
