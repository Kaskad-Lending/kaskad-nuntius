# EU <-> US fleet peering for oracle RA-TLS handover (8443, SG-scoped in the module).

resource "aws_vpc_peering_connection" "us" {
  vpc_id      = module.fleet.vpc_id
  peer_vpc_id = local.us.vpc_id
  peer_region = local.us.aws_region

  tags = { Name = "${var.name_prefix}-to-us" }
}

resource "aws_vpc_peering_connection_accepter" "us" {
  provider                  = aws.us
  vpc_peering_connection_id = aws_vpc_peering_connection.us.id
  auto_accept               = true

  tags = { Name = "${var.name_prefix}-to-us" }
}

# Routes reference the accepter so they wait for an active connection.
resource "aws_route" "to_us" {
  route_table_id            = module.fleet.public_route_table_id
  destination_cidr_block    = local.us.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.us.id
}

resource "aws_route" "from_us" {
  provider                  = aws.us
  route_table_id            = local.us.public_route_table_id
  destination_cidr_block    = module.fleet.vpc_cidr
  vpc_peering_connection_id = aws_vpc_peering_connection_accepter.us.id
}
