# ─── Builder EC2 (stopped by default) ─────────────────────────

resource "aws_instance" "builder" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public_a.id
  vpc_security_group_ids = [aws_security_group.builder.id]
  iam_instance_profile   = aws_iam_instance_profile.builder.name

  enclave_options {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # No SSH key — zero interactive access.

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = base64encode(templatefile("${path.module}/user-data-builder.sh", {
    eif_bucket  = var.eif_bucket_name
    aws_region  = var.aws_region
    github_org  = var.github_org
    github_repo = var.github_repo
  }))

  user_data_replace_on_change = true

  tags = {
    Name        = "${var.name_prefix}-builder"
    BuildCommit = "none" # Updated by CI before starting.
  }

  lifecycle {
    ignore_changes = [tags["BuildCommit"]]
  }
}

# Terraform creates the builder running; stop it after creation.
resource "null_resource" "stop_builder" {
  depends_on = [aws_instance.builder]

  provisioner "local-exec" {
    command = "aws ec2 stop-instances --instance-ids ${aws_instance.builder.id} --region ${var.aws_region}"
  }
}
