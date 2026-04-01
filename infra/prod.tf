# ─── Prod: Spot ASG + Launch Template ─────────────────────────

resource "aws_launch_template" "prod" {
  name_prefix   = "${var.project_name}-prod-"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = var.instance_type

  # Nitro Enclave
  enclave_options {
    enabled = true
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
    eif_bucket          = var.eif_bucket_name
    enclave_cpu_count   = var.enclave_cpu_count
    enclave_memory_mib  = var.enclave_memory_mib
    pull_api_script     = file("${path.module}/../enclave/pull_api.py")
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-prod"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "prod" {
  name                = "${var.project_name}-prod-asg"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 1
  vpc_zone_identifier = [aws_subnet.public.id]

  # Spot instances
  mixed_instances_policy {
    instances_distribution {
      on_demand_base_capacity                  = 0
      on_demand_percentage_above_base_capacity = 0
      spot_allocation_strategy                 = "capacity-optimized"
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
    value               = "${var.project_name}-prod-asg"
    propagate_at_launch = false
  }
}
