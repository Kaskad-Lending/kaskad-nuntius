# /kaskad/nitro* only — never /kaskad/oracle*. The fleet log group and the
# quorum alarm live in the nitro-fleet module.

resource "aws_cloudwatch_log_group" "nitro_builder" {
  name              = "/kaskad/nitro-builder"
  retention_in_days = 7

  tags = { Name = "${var.name_prefix}-builder-logs" }
}
