# Least-privilege roles. Every role carries the KaskadNitroBoundary
# permissions boundary — kaskad-tf apply is denied otherwise.

# ─── Prod EC2 Role ────────────────────────────────────────────

resource "aws_iam_role" "prod" {
  name                 = "${var.name_prefix}-prod"
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

resource "aws_iam_role_policy" "prod" {
  name = "${var.name_prefix}-prod-policy"
  role = aws_iam_role.prod.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadEIF"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.eif.arn}/*"]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = ["${aws_cloudwatch_log_group.nitro.arn}:*"]
      },
      {
        Sid      = "CloudWatchMetrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = ["*"]
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "KaskadNitro" }
        }
      },
      {
        Sid    = "SSMSession"
        Effect = "Allow"
        Action = [
          "ssm:UpdateInstanceInformation",
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = ["*"]
      },
      {
        # pontifex_host.py sweeps same-ASG peers for the config loop. Describe*
        # has no resource-level scoping (mirrors the github_ci role).
        Sid      = "DescribeSelfPeers"
        Effect   = "Allow"
        Action   = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeTags"]
        Resource = ["*"]
      },
      {
        # pontifex_host.py lists s3://<bucket>/approvals/ (owner-signed keyex
        # handover approvals). GetObject on the objects is covered by ReadEIF.
        Sid      = "ListApprovals"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.eif.arn]
        Condition = {
          StringLike = { "s3:prefix" = ["approvals/*"] }
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "prod" {
  name = "${var.name_prefix}-prod"
  role = aws_iam_role.prod.name
}

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
    Statement = [
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:PutObjectTagging"]
        Resource = [
          aws_s3_bucket.eif.arn,
          "${aws_s3_bucket.eif.arn}/*"
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
    ]
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
      {
        Sid    = "BuilderSSM"
        Effect = "Allow"
        Action = [
          "ssm:SendCommand",
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
      {
        Sid      = "ReadWriteBuildArtifacts"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["${aws_s3_bucket.eif.arn}/*"]
      },
      {
        Sid      = "RefreshASG"
        Effect   = "Allow"
        Action   = ["autoscaling:StartInstanceRefresh"]
        Resource = ["*"]
        Condition = {
          StringEquals = { "autoscaling:ResourceTag/Name" = "${var.name_prefix}-prod-asg" }
        }
      }
    ]
  })
}
