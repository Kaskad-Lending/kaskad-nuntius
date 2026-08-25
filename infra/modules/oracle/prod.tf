# ─── Prod: Spot ASG + Launch Template ─────────────────────────

resource "aws_launch_template" "prod" {
  name_prefix   = "${var.name_prefix}-prod-"
  image_id      = var.ami_id
  instance_type = var.instance_type

  # Nitro Enclave
  enclave_options {
    enabled = true
  }

  # IMDSv2-only. `http_tokens = "required"` forces the session-token
  # handshake on every metadata read, defeating trivial SSRF-based IAM
  # credential theft. `http_put_response_hop_limit = 1` keeps a
  # compromised host-side service (e.g. pull_api.py) from forwarding
  # metadata responses through an extra network hop.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # No SSH key
  # key_name = ""

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
    eif_bucket         = var.eif_bucket_name
    enclave_cpu_count  = var.enclave_cpu_count
    enclave_memory_mib = var.enclave_memory_mib
    vpc_cidr           = var.vpc_cidr
    trusted_proxies    = join(",", var.trusted_proxies)
    aws_region         = var.aws_region
    kms_sealing_alias  = aws_kms_alias.sealing.name
    kms_release_alias  = aws_kms_alias.release.name
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.name_prefix}-prod"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "prod" {
  name                = "${var.name_prefix}-prod-asg"
  desired_capacity    = var.asg_capacity
  min_size            = var.asg_capacity
  max_size            = 1
  vpc_zone_identifier = [aws_subnet.public.id]

  # On-demand for stability — pure spot kept reclaiming the instance
  # every few days, and each reclaim regenerates the enclave key
  # (no key sealing yet) which forces a full Mock-verifier + Oracle +
  # aggregators redeploy. Overrides retained as a fallback pool in case
  # AWS runs out of c5.xlarge on-demand capacity in our AZ.
  mixed_instances_policy {
    instances_distribution {
      on_demand_base_capacity                  = 1
      on_demand_percentage_above_base_capacity = 100
    }

    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.prod.id
        version            = "$Latest"
      }

      override {
        instance_type = "c5.xlarge"
      }
      override {
        instance_type = "c5a.xlarge"
      }
      override {
        instance_type = "c5d.xlarge"
      }
      override {
        instance_type = "m5.xlarge"
      }
    }
  }

  # Auto-replace unhealthy
  health_check_type         = "EC2"
  health_check_grace_period = 300

  # Instance refresh for deployments
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 0 # Allow full replacement (single instance)
    }
  }

  # Publish ASG metrics to CloudWatch (required for alarms)
  enabled_metrics = ["GroupInServiceInstances", "GroupDesiredCapacity", "GroupTotalInstances"]

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-prod-asg"
    propagate_at_launch = false
  }
}
