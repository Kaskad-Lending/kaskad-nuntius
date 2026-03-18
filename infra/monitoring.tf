# ─── CloudWatch Log Group ─────────────────────────────────────

resource "aws_cloudwatch_log_group" "oracle" {
  name              = "/kaskad/oracle"
  retention_in_days = 30

  tags = { Name = "${var.project_name}-logs" }
}

resource "aws_cloudwatch_log_group" "builder" {
  name              = "/kaskad/builder"
  retention_in_days = 7

  tags = { Name = "${var.project_name}-builder-logs" }
}

# ─── CloudWatch Alarms ────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "no_instances" {
  alarm_name          = "${var.project_name}-no-running-instances"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "GroupInServiceInstances"
  namespace           = "AWS/AutoScaling"
  period              = 300
  statistic           = "Minimum"
  threshold           = 1
  alarm_description   = "No oracle instances running in ASG"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.prod.name
  }

  # TODO: Add SNS topic for notifications
  # alarm_actions = [aws_sns_topic.alerts.arn]
}
