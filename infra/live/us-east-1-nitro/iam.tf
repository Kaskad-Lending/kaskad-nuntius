# Least-privilege roles. Every role carries the KaskadNitroBoundary
# permissions boundary — kaskad-tf apply is denied otherwise.

# ─── Builder EC2 Role ─────────────────────────────────────────

resource "aws_iam_role" "builder" {
  name                 = "${var.name_prefix}-builder"
  permissions_boundary = var.permissions_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "builder_ssm" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.builder.name
}

resource "aws_iam_role_policy" "builder" {
  name = "${var.name_prefix}-builder-policy"
  role = aws_iam_role.builder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:PutObjectTagging"]
        Resource = [
          module.eif_bucket.arn,
          "${module.eif_bucket.arn}/*"
        ]
      },
      {
        Sid      = "SelfStop"
        Effect   = "Allow"
        Action   = ["ec2:StopInstances"]
        Resource = ["*"]
        Condition = {
          StringEquals = { "ec2:ResourceTag/Name" = "${var.name_prefix}-builder" }
        }
      },
      {
        Sid      = "ReadOwnTags"
        Effect   = "Allow"
        Action   = ["ec2:DescribeTags"]
        Resource = ["*"]
      }
      ], length(var.eif_mirror_buckets) == 0 ? [] : [
      {
        # Boot artifacts only; builds/ and staging/ stay in the release bucket.
        Sid    = "MirrorBootArtifacts"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = flatten([for b in var.eif_mirror_buckets : [
          "arn:aws:s3:::${b}/eif/*",
          "arn:aws:s3:::${b}/host*/*",
        ]])
      }
    ])
  })
}

resource "aws_iam_instance_profile" "builder" {
  name = "${var.name_prefix}-builder"
  role = aws_iam_role.builder.name
}

# ─── GitHub Actions OIDC Role ─────────────────────────────────
# OIDC provider is account-scoped and reused via var.oidc_provider_arn;
# this root never creates one.

resource "aws_iam_role" "github_ci" {
  name                 = "${var.name_prefix}-github-ci"
  permissions_boundary = var.permissions_boundary_arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = var.oidc_provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "github_ci" {
  name = "${var.name_prefix}-github-ci-policy"
  role = aws_iam_role.github_ci.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "BuilderLifecycle"
        Effect   = "Allow"
        Action   = ["ec2:StartInstances", "ec2:StopInstances", "ec2:CreateTags"]
        Resource = ["*"]
        Condition = {
          StringEquals = { "ec2:ResourceTag/Name" = "${var.name_prefix}-builder" }
        }
      },
      # SendCommand is root on the target. Scope it to the builder by tag, the
      # same condition BuilderLifecycle above already uses; an unscoped
      # Resource would hand CI root on the prod ASG as well.
      {
        Sid      = "BuilderSSMSend"
        Effect   = "Allow"
        Action   = ["ssm:SendCommand"]
        Resource = ["arn:aws:ec2:${var.aws_region}:*:instance/*"]
        Condition = {
          StringEquals = { "ssm:resourceTag/Name" = "${var.name_prefix}-builder" }
        }
      },
      {
        Sid      = "BuilderSSMDocument"
        Effect   = "Allow"
        Action   = ["ssm:SendCommand"]
        Resource = ["arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript"]
      },
      {
        Sid    = "BuilderSSMRead"
        Effect = "Allow"
        Action = [
          "ssm:GetCommandInvocation",
          "ssm:ListCommands",
          "ssm:ListCommandInvocations",
          "ssm:DescribeInstanceInformation"
        ]
        Resource = ["*"]
      },
      {
        Sid      = "DescribeInstances"
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeTags"]
        Resource = ["*"]
      },
      # No autoscaling grant: a rolling refresh can terminate the last enclave
      # holding the key. Fleet rolls are manual scale-out -> handover -> scale-in.
      {
        Sid      = "ReadWriteBuildArtifacts"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["${module.eif_bucket.arn}/*"]
      }
    ]
  })
}
