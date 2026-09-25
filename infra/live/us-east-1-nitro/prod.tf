# ─── Prod: two-AZ ASG + Launch Template ──────────────────────

resource "aws_launch_template" "prod" {
  name_prefix   = "${var.name_prefix}-prod-"
  image_id      = var.ami_id
  instance_type = var.instance_type

  enclave_options {
    enabled = true
  }

  # IMDSv2-only: required token defeats SSRF IAM theft; hop_limit=1
  # keeps a compromised host service from proxying metadata.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.prod.name
  }

  vpc_security_group_ids = [aws_security_group.prod.id]

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 30
      volume_type = "gp3"
    }
  }

  user_data = base64encode(templatefile("${path.module}/user-data-prod.sh", {
    eif_bucket          = var.eif_bucket_name
    aws_region          = var.aws_region
    kms_release_alias   = aws_kms_alias.release.name
    oracle_cpu_count    = var.enclave_cpu_count
    oracle_memory_mib   = var.enclave_memory_mib
    pontifex_cpu_count  = var.pontifex_cpu_count
    pontifex_memory_mib = var.pontifex_memory_mib
    # Allocator pool must cover BOTH enclaves at once (+512 MiB host/hugepage margin).
    allocator_cpu_count  = var.enclave_cpu_count + var.pontifex_cpu_count
    allocator_memory_mib = var.enclave_memory_mib + var.pontifex_memory_mib + 512
    # Host relay-plane config (untrusted hints).
    vpc_cidr        = var.vpc_cidr
    oracle_registry = var.oracle_registry
    bridge_entry    = var.bridge_entry
    rh_rpcs         = var.rh_rpcs
    # String literal, NOT aws_autoscaling_group.prod.name — a resource ref would
    # form an ASG -> LT -> user-data -> ASG cycle.
    asg_name = "${var.name_prefix}-prod-asg"
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "${var.name_prefix}-prod" }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "prod" {
  name                = "${var.name_prefix}-prod-asg"
  desired_capacity    = var.asg_capacity
  min_size            = var.asg_capacity
  max_size            = var.asg_max_size
  vpc_zone_identifier = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  # On-demand for stability; spot pool kept as capacity fallback.
  mixed_instances_policy {
    instances_distribution {
      on_demand_base_capacity                  = var.asg_capacity
      on_demand_percentage_above_base_capacity = 100
    }

    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.prod.id
        # Numeric pin, not $Latest: boundary DenyFloatingLtVersion blocks floating
        # versions (closes the LT-version PassRole bypass). Repins each apply.
        version = tostring(aws_launch_template.prod.latest_version)
      }

      override { instance_type = "c5.2xlarge" }
      override { instance_type = "c5a.2xlarge" }
      override { instance_type = "c5d.2xlarge" }
      override { instance_type = "m5.2xlarge" }
    }
  }

  health_check_type         = "EC2"
  health_check_grace_period = 300

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50 # Two-AZ: keep one instance serving during refresh.
    }
  }

  enabled_metrics = ["GroupInServiceInstances", "GroupDesiredCapacity", "GroupTotalInstances"]

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-prod-asg"
    propagate_at_launch = false
  }
}
