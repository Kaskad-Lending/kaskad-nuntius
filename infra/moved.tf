# State migration: flat config -> module "oracle_us_east_1".
# Generated for the modules/oracle refactor — terraform moves each
# existing resource into the module address; no infrastructure changes.
# The data sources and aws_iam_openid_connect_provider.github keep
# their root-level addresses and need no moved block.

moved {
  from = aws_acm_certificate.oracle
  to   = module.oracle_us_east_1.aws_acm_certificate.oracle
}

moved {
  from = aws_autoscaling_attachment.oracle
  to   = module.oracle_us_east_1.aws_autoscaling_attachment.oracle
}

moved {
  from = aws_autoscaling_group.prod
  to   = module.oracle_us_east_1.aws_autoscaling_group.prod
}

moved {
  from = aws_cloudwatch_log_group.builder
  to   = module.oracle_us_east_1.aws_cloudwatch_log_group.builder
}

moved {
  from = aws_cloudwatch_log_group.oracle
  to   = module.oracle_us_east_1.aws_cloudwatch_log_group.oracle
}

moved {
  from = aws_cloudwatch_metric_alarm.no_instances
  to   = module.oracle_us_east_1.aws_cloudwatch_metric_alarm.no_instances
}

moved {
  from = aws_iam_instance_profile.builder
  to   = module.oracle_us_east_1.aws_iam_instance_profile.builder
}

moved {
  from = aws_iam_instance_profile.prod
  to   = module.oracle_us_east_1.aws_iam_instance_profile.prod
}

moved {
  from = aws_iam_role.builder
  to   = module.oracle_us_east_1.aws_iam_role.builder
}

moved {
  from = aws_iam_role.github_ci
  to   = module.oracle_us_east_1.aws_iam_role.github_ci
}

moved {
  from = aws_iam_role_policy_attachment.builder_ssm
  to   = module.oracle_us_east_1.aws_iam_role_policy_attachment.builder_ssm
}

moved {
  from = aws_iam_role_policy.builder
  to   = module.oracle_us_east_1.aws_iam_role_policy.builder
}

moved {
  from = aws_iam_role_policy.builder_kms_sign
  to   = module.oracle_us_east_1.aws_iam_role_policy.builder_kms_sign
}

moved {
  from = aws_iam_role_policy.github_ci
  to   = module.oracle_us_east_1.aws_iam_role_policy.github_ci
}

moved {
  from = aws_iam_role_policy.github_ci_kms_sign
  to   = module.oracle_us_east_1.aws_iam_role_policy.github_ci_kms_sign
}

moved {
  from = aws_iam_role_policy.prod
  to   = module.oracle_us_east_1.aws_iam_role_policy.prod
}

moved {
  from = aws_iam_role_policy.prod_kms_verify
  to   = module.oracle_us_east_1.aws_iam_role_policy.prod_kms_verify
}

moved {
  from = aws_iam_role.prod
  to   = module.oracle_us_east_1.aws_iam_role.prod
}

moved {
  from = aws_instance.builder
  to   = module.oracle_us_east_1.aws_instance.builder
}

moved {
  from = aws_internet_gateway.main
  to   = module.oracle_us_east_1.aws_internet_gateway.main
}

moved {
  from = aws_kms_alias.release
  to   = module.oracle_us_east_1.aws_kms_alias.release
}

moved {
  from = aws_kms_alias.sealing
  to   = module.oracle_us_east_1.aws_kms_alias.sealing
}

moved {
  from = aws_kms_key.release
  to   = module.oracle_us_east_1.aws_kms_key.release
}

moved {
  from = aws_kms_key.sealing
  to   = module.oracle_us_east_1.aws_kms_key.sealing
}

moved {
  from = aws_launch_template.prod
  to   = module.oracle_us_east_1.aws_launch_template.prod
}

moved {
  from = aws_lb_listener.http_redirect
  to   = module.oracle_us_east_1.aws_lb_listener.http_redirect
}

moved {
  from = aws_lb_listener.https
  to   = module.oracle_us_east_1.aws_lb_listener.https
}

moved {
  from = aws_lb.oracle
  to   = module.oracle_us_east_1.aws_lb.oracle
}

moved {
  from = aws_lb_target_group.oracle
  to   = module.oracle_us_east_1.aws_lb_target_group.oracle
}

moved {
  from = aws_route_table_association.public
  to   = module.oracle_us_east_1.aws_route_table_association.public
}

moved {
  from = aws_route_table_association.public_b
  to   = module.oracle_us_east_1.aws_route_table_association.public_b
}

moved {
  from = aws_route_table.public
  to   = module.oracle_us_east_1.aws_route_table.public
}

moved {
  from = aws_s3_bucket.eif
  to   = module.oracle_us_east_1.aws_s3_bucket.eif
}

moved {
  from = aws_s3_bucket_public_access_block.eif
  to   = module.oracle_us_east_1.aws_s3_bucket_public_access_block.eif
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.eif
  to   = module.oracle_us_east_1.aws_s3_bucket_server_side_encryption_configuration.eif
}

moved {
  from = aws_s3_bucket_versioning.eif
  to   = module.oracle_us_east_1.aws_s3_bucket_versioning.eif
}

moved {
  from = aws_security_group.alb
  to   = module.oracle_us_east_1.aws_security_group.alb
}

moved {
  from = aws_security_group.builder
  to   = module.oracle_us_east_1.aws_security_group.builder
}

moved {
  from = aws_security_group.prod
  to   = module.oracle_us_east_1.aws_security_group.prod
}

moved {
  from = aws_subnet.public
  to   = module.oracle_us_east_1.aws_subnet.public
}

moved {
  from = aws_subnet.public_b
  to   = module.oracle_us_east_1.aws_subnet.public_b
}

moved {
  from = aws_vpc.main
  to   = module.oracle_us_east_1.aws_vpc.main
}

moved {
  from = null_resource.stop_builder
  to   = module.oracle_us_east_1.null_resource.stop_builder
}

