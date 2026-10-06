# Fleet resources moved into module.fleet; terraform re-addresses state only.

moved {
  from = aws_vpc.main
  to   = module.fleet.aws_vpc.main
}

moved {
  from = aws_internet_gateway.main
  to   = module.fleet.aws_internet_gateway.main
}

moved {
  from = aws_subnet.public_a
  to   = module.fleet.aws_subnet.public_a
}

moved {
  from = aws_subnet.public_b
  to   = module.fleet.aws_subnet.public_b
}

moved {
  from = aws_route_table.public
  to   = module.fleet.aws_route_table.public
}

moved {
  from = aws_route_table_association.public_a
  to   = module.fleet.aws_route_table_association.public_a
}

moved {
  from = aws_route_table_association.public_b
  to   = module.fleet.aws_route_table_association.public_b
}

moved {
  from = aws_security_group.prod
  to   = module.fleet.aws_security_group.prod
}

moved {
  from = aws_security_group.alb
  to   = module.fleet.aws_security_group.alb
}

moved {
  from = aws_acm_certificate.nitro
  to   = module.fleet.aws_acm_certificate.nitro
}

moved {
  from = aws_lb.nitro
  to   = module.fleet.aws_lb.nitro
}

moved {
  from = aws_lb_target_group.nitro
  to   = module.fleet.aws_lb_target_group.nitro
}

moved {
  from = aws_lb_target_group.bridge
  to   = module.fleet.aws_lb_target_group.bridge
}

moved {
  from = aws_lb_listener.https
  to   = module.fleet.aws_lb_listener.https
}

moved {
  from = aws_lb_listener.http_redirect
  to   = module.fleet.aws_lb_listener.http_redirect
}

moved {
  from = aws_lb_listener.http_forward
  to   = module.fleet.aws_lb_listener.http_forward
}

moved {
  from = aws_lb_listener_rule.bridge_read
  to   = module.fleet.aws_lb_listener_rule.bridge_read
}

moved {
  from = aws_lb_listener_rule.bridge_sign
  to   = module.fleet.aws_lb_listener_rule.bridge_sign
}

moved {
  from = aws_autoscaling_attachment.nitro
  to   = module.fleet.aws_autoscaling_attachment.nitro
}

moved {
  from = aws_autoscaling_attachment.bridge
  to   = module.fleet.aws_autoscaling_attachment.bridge
}

moved {
  from = aws_launch_template.prod
  to   = module.fleet.aws_launch_template.prod
}

moved {
  from = aws_autoscaling_group.prod
  to   = module.fleet.aws_autoscaling_group.prod
}

moved {
  from = aws_iam_role.prod
  to   = module.fleet.aws_iam_role.prod
}

moved {
  from = aws_iam_role_policy.prod
  to   = module.fleet.aws_iam_role_policy.prod
}

moved {
  from = aws_iam_instance_profile.prod
  to   = module.fleet.aws_iam_instance_profile.prod
}

moved {
  from = aws_cloudwatch_log_group.nitro
  to   = module.fleet.aws_cloudwatch_log_group.nitro
}

moved {
  from = aws_cloudwatch_metric_alarm.quorum
  to   = module.fleet.aws_cloudwatch_metric_alarm.quorum
}
