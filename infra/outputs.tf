output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "prod_asg_name" {
  value = aws_autoscaling_group.prod.name
}

output "builder_instance_id" {
  value = aws_instance.builder.id
}

output "eif_bucket" {
  value = aws_s3_bucket.eif.bucket
}

output "prod_security_group" {
  value = aws_security_group.prod.id
}

output "github_oidc_role_arn" {
  value = aws_iam_role.github_ci.arn
}

# ─── Data Sources ─────────────────────────────────────────────

data "aws_caller_identity" "current" {}

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}
