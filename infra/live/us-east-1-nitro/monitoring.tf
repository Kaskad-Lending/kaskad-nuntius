# ─── CloudWatch Log Groups ────────────────────────────────────
# /kaskad/nitro* only — never /kaskad/oracle* or /kaskad/builder*.

resource "aws_cloudwatch_log_group" "nitro" {
  name              = "/kaskad/nitro"
  retention_in_days = 30

  tags = { Name = "${var.name_prefix}-logs" }
}

resource "aws_cloudwatch_log_group" "nitro_builder" {
  name              = "/kaskad/nitro-builder"
  retention_in_days = 7

  tags = { Name = "${var.name_prefix}-builder-logs" }
}

# ─── CloudWatch Alarms ────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "quorum" {
  alarm_name          = "${var.name_prefix}-below-quorum"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "GroupInServiceInstances"
  namespace           = "AWS/AutoScaling"
  period              = 300
  statistic           = "Minimum"
  threshold           = var.asg_capacity
  alarm_description   = "Nitro fleet below keyex quorum floor"
  treat_missing_data  = "breaching"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.prod.name
  }

  # TODO: wire alarm_actions to an SNS topic.
}
