# ═══════════════════════════════════════════════════════════════
# IAM — Least Privilege Roles
# ═══════════════════════════════════════════════════════════════

# ─── Prod EC2 Role ────────────────────────────────────────────

resource "aws_iam_role" "prod" {
  name = "${var.project_name}-prod"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "prod" {
  name = "${var.project_name}-prod-policy"
  role = aws_iam_role.prod.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadEIF"
        Effect = "Allow"
        Action = ["s3:GetObject"]
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
        Resource = ["${aws_cloudwatch_log_group.oracle.arn}:*"]
      },
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = ["cloudwatch:PutMetricData"]
        Resource = ["*"]
        Condition = {
          StringEquals = { "cloudwatch:namespace" = "KaskadOracle" }
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
      }
    ]
  })
}

resource "aws_iam_instance_profile" "prod" {
  name = "${var.project_name}-prod"
  role = aws_iam_role.prod.name
}

# ─── Builder EC2 Role ─────────────────────────────────────────

resource "aws_iam_role" "builder" {
  name = "${var.project_name}-builder"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "builder_ssm" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.builder.name
}

resource "aws_iam_role_policy" "builder" {
  name = "${var.project_name}-builder-policy"
  role = aws_iam_role.builder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:PutObjectTagging"
        ]
        Resource = [
          aws_s3_bucket.eif.arn,
          "${aws_s3_bucket.eif.arn}/*"
        ]
      },
      {
        Sid    = "SelfStop"
        Effect = "Allow"
        Action = ["ec2:StopInstances"]
        Resource = ["*"]
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Name" = "${var.project_name}-builder"
          }
        }
      },
      {
        Sid    = "ReadOwnTags"
        Effect = "Allow"
        Action = ["ec2:DescribeTags"]
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "builder" {
  name = "${var.project_name}-builder"
  role = aws_iam_role.builder.name
}

# ─── GitHub Actions OIDC Role ─────────────────────────────────

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["ffffffffffffffffffffffffffffffffffffffff"]
}

resource "aws_iam_role" "github_ci" {
  name = "${var.project_name}-github-ci"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
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
  name = "${var.project_name}-github-ci-policy"
  role = aws_iam_role.github_ci.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StartBuilder"
        Effect = "Allow"
        Action = [
          "ec2:StartInstances",
          "ec2:CreateTags"
        ]
        Resource = ["*"]
        Condition = {
          StringEquals = {
            "ec2:ResourceTag/Name" = "${var.project_name}-builder"
          }
        }
      },
      {
        Sid    = "DescribeInstances"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeTags"
        ]
        Resource = ["*"]
      },
      {
        Sid    = "ReadWriteBuildArtifacts"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = ["${aws_s3_bucket.eif.arn}/*"]
      },
      {
        Sid    = "RefreshASG"
        Effect = "Allow"
        Action = ["autoscaling:StartInstanceRefresh"]
        Resource = ["*"]
        Condition = {
          StringEquals = {
            "autoscaling:ResourceTag/Name" = "${var.project_name}-prod-asg"
          }
        }
      }
    ]
  })
}
