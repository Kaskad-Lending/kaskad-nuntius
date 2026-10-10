# Builder-only network. The fleet VPC (var.vpc_cidr) lives in the pin-gated module,
# but the builder produces the first pins, so it cannot live there.

resource "aws_vpc" "builder" {
  cidr_block           = var.builder_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.name_prefix}-builder-vpc" }
}

resource "aws_internet_gateway" "builder" {
  vpc_id = aws_vpc.builder.id
  tags   = { Name = "${var.name_prefix}-builder-igw" }
}

resource "aws_subnet" "builder" {
  vpc_id                  = aws_vpc.builder.id
  cidr_block              = cidrsubnet(var.builder_vpc_cidr, 8, 1)
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = { Name = "${var.name_prefix}-builder-public-a" }
}

resource "aws_route_table" "builder" {
  vpc_id = aws_vpc.builder.id
  tags   = { Name = "${var.name_prefix}-builder-rt" }
}

resource "aws_route" "builder_internet" {
  route_table_id         = aws_route_table.builder.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.builder.id
}

resource "aws_route_table_association" "builder" {
  subnet_id      = aws_subnet.builder.id
  route_table_id = aws_route_table.builder.id
}
