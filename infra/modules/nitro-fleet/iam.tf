# Prod instance role. Carries KaskadNitroBoundary — kaskad-tf apply is denied otherwise.

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

locals {
  eif_bucket_arn = "arn:aws:s3:::${var.eif_bucket_name}"
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
        Resource = ["${local.eif_bucket_arn}/*"]
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
        # pontifex_host.py lists approvals/ (owner-signed keyex handover
        # approvals). GetObject on the objects is covered by ReadEIF.
        Sid      = "ListApprovals"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [local.eif_bucket_arn]
        Condition = {
          StringLike = { "s3:prefix" = ["approvals/*"] }
        }
      },
      {
        # Public attestations to genesis/ and bridge/, allocator diagnostics to
        # diag/. PutObject only on those prefixes, never bucket-wide.
        Sid    = "PublishAttestations"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = [
          "${local.eif_bucket_arn}/genesis/*",
          "${local.eif_bucket_arn}/bridge/*",
          "${local.eif_bucket_arn}/diag/*",
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "prod" {
  name = "${var.name_prefix}-prod"
  role = aws_iam_role.prod.name
}
