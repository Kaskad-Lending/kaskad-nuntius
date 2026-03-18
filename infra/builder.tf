# ─── Builder EC2 (stopped by default) ─────────────────────────

resource "aws_instance" "builder" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.builder.id]
  iam_instance_profile   = aws_iam_instance_profile.builder.name

  # Nitro Enclave support (needed to build EIF)
  enclave_options {
    enabled = true
  }

  # No SSH key — zero access
  # key_name = "" # intentionally omitted

  root_block_device {
    volume_size = 30 # GB, enough for Docker build
    volume_type = "gp3"
  }

  user_data = base64encode(templatefile("${path.module}/user-data-builder.sh", {
    eif_bucket  = var.eif_bucket_name
    aws_region  = var.aws_region
    github_org  = var.github_org
    github_repo = var.github_repo
  }))

  tags = {
    Name        = "${var.project_name}-builder"
    BuildCommit = "none" # Updated by CI before starting
  }

  # Start stopped — CI will start it
  lifecycle {
    ignore_changes = [tags["BuildCommit"]]
  }
}

# Stop builder after creation (Terraform creates it running)
resource "null_resource" "stop_builder" {
  depends_on = [aws_instance.builder]

  provisioner "local-exec" {
    command = "aws ec2 stop-instances --instance-ids ${aws_instance.builder.id} --region ${var.aws_region}"
  }
}
