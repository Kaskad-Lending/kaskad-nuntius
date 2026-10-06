# ─── Builder EC2 (stopped by default) ─────────────────────────

resource "aws_instance" "builder" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = module.fleet.public_subnet_ids[0]
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

resource "aws_security_group" "builder" {
  name_prefix = "${var.name_prefix}-builder-"
  description = "Builder: NO inbound, HTTPS/HTTP outbound for git/docker/S3"
  vpc_id      = module.fleet.vpc_id

  # NO ingress — no SSH.

  egress {
    description = "HTTPS (git, Docker Hub, S3)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-builder-sg" }

  lifecycle {
    create_before_destroy = true
  }
}
