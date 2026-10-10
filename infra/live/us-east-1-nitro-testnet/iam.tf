# Least-privilege roles, all kaskad-nitro-* with KaskadNitroBoundary (kaskad-tf
# may create roles only that way). Inline policies only; PassRole is EC2-only.

locals {
  # Locals, not variables: a tfvars override must not widen the CI trust.
  github_org  = "Kaskad-Lending"
  github_repo = "kaskad-nuntius"
  # Testnet release tags only; eif-v* (mainnet build-eif.yml) never matches.
  release_ref   = "refs/tags/eif-testnet-v*"
  instance_arns = "arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"
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

# The builder does every upload, so this bucket-only grant is what keeps a
# testnet release out of the mainnet buckets.
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
          module.eif_bucket.arn,
          "${module.eif_bucket.arn}/*"
        ]
      },
      {
        Sid      = "SelfStop"
        Effect   = "Allow"
        Action   = ["ec2:StopInstances"]
        Resource = [local.instance_arns]
        Condition = {
          StringEquals = { "ec2:ResourceTag/Name" = local.builder_tag }
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

resource "aws_iam_role" "github_ci" {
  name                 = "${var.name_prefix}-github-ci"
  permissions_boundary = var.permissions_boundary_arn

  # A job with `environment:` gets an environment sub and is refused, by design.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:${local.github_org}/${local.github_repo}:ref:${local.release_ref}"
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
      # No ec2:CreateTags: build-eif-testnet.yml never tags the builder.
      {
        Sid      = "BuilderLifecycle"
        Effect   = "Allow"
        Action   = ["ec2:StartInstances", "ec2:StopInstances"]
        Resource = [local.instance_arns]
        Condition = {
          StringEquals = { "ec2:ResourceTag/Name" = local.builder_tag }
        }
      },
      # SendCommand is root on the target: the testnet builder tag only, never the fleet.
      {
        Sid      = "BuilderSSMSend"
        Effect   = "Allow"
        Action   = ["ssm:SendCommand"]
        Resource = [local.instance_arns]
        Condition = {
          StringEquals = { "ssm:resourceTag/Name" = local.builder_tag }
        }
      },
      {
        Sid      = "BuilderSSMDocument"
        Effect   = "Allow"
        Action   = ["ssm:SendCommand"]
        Resource = ["arn:aws:ssm:${var.aws_region}::document/AWS-RunShellScript"]
      },
      # Read-only calls that take no resource-level scoping.
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
      # No autoscaling grant: fleet rolls are manual scale-out -> handover -> scale-in.
      {
        Sid      = "ReadWriteBuildArtifacts"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = ["${module.eif_bucket.arn}/*"]
      }
    ]
  })
}
