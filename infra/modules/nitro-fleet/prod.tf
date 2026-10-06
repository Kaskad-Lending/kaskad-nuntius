# ─── Prod: two-AZ ASG + Launch Template ──────────────────────

# ASG launches do not inherit provider default_tags; Project gates SSM in the boundary.
data "aws_default_tags" "current" {}

locals {
  artifact_region = coalesce(var.artifact_region, var.aws_region)
  instance_tags   = merge(data.aws_default_tags.current.tags, { Name = "${var.name_prefix}-prod" })
}

resource "aws_launch_template" "prod" {
  name_prefix   = "${var.name_prefix}-prod-"
  image_id      = var.ami_id
  instance_type = var.instance_types[0]

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
    eif_release_suffix  = var.eif_release_suffix
    aws_region          = var.aws_region
    artifact_region     = local.artifact_region
    oracle_sha384       = var.oracle_eif.sha384
    oracle_pcr0         = var.oracle_eif.pcr0
    pontifex_sha384     = try(var.pontifex_eif.sha384, "")
    pontifex_pcr0       = try(var.pontifex_eif.pcr0, "")
    log_group           = aws_cloudwatch_log_group.nitro.name
    enclave_debug_mode  = var.enclave_debug_mode
    oracle_cpu_count    = var.enclave_cpu_count
    oracle_memory_mib   = var.enclave_memory_mib
    pontifex_cpu_count  = var.pontifex_cpu_count
    pontifex_memory_mib = var.pontifex_memory_mib
    enable_pontifex     = var.enable_pontifex
    # Allocator pool covers every enclave that boots, at once (+512 MiB
    # host/hugepage margin); reserving for an unbooted bridge strands two cores.
    allocator_cpu_count  = var.enclave_cpu_count + (var.enable_pontifex ? var.pontifex_cpu_count : 0)
    allocator_memory_mib = var.enclave_memory_mib + (var.enable_pontifex ? var.pontifex_memory_mib : 0) + 512
    # Host relay-plane config (untrusted hints).
    vpc_cidr         = var.vpc_cidr
    edge_domain_name = var.edge_domain_name
    oracle_registry  = var.oracle_registry
    bridge_entry     = var.bridge_entry
    rh_rpcs          = var.rh_rpcs
    # String literal, NOT aws_autoscaling_group.prod.name — a resource ref would
    # form an ASG -> LT -> user-data -> ASG cycle.
    asg_name  = "${var.name_prefix}-prod-asg"
    peer_asgs = join(",", [for p in var.peer_asgs : "${p.region}:${p.asg_name}"])
  }))

  tag_specifications {
    resource_type = "instance"
    tags          = local.instance_tags
  }

  tag_specifications {
    resource_type = "volume"
    tags          = local.instance_tags
  }

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = !var.enable_pontifex || var.pontifex_eif != null
      error_message = "enable_pontifex needs a pontifex_eif pin."
    }
  }
}

resource "aws_autoscaling_group" "prod" {
  name                = "${var.name_prefix}-prod-asg"
  desired_capacity    = var.asg_capacity
  min_size            = var.asg_capacity
  max_size            = var.asg_max_size
  vpc_zone_identifier = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  # On-demand for stability; the fallback types cover a capacity shortage.
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

      dynamic "override" {
        for_each = var.instance_types
        content {
          instance_type = override.value
        }
      }
    }
  }

  health_check_type         = "EC2"
  health_check_grace_period = 300

  # No instance_refresh on purpose: k_root lives only in enclave memory and the
  # EC2 health check marks an instance InService long before its enclave holds
  # the key, so a rolling replace can terminate the last key holder. Roll by
  # scaling out, letting the new enclave take the key over RA-TLS, then in.

  enabled_metrics = ["GroupInServiceInstances", "GroupDesiredCapacity", "GroupTotalInstances"]

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-prod-asg"
    propagate_at_launch = false
  }
}
