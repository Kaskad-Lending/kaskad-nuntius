data "aws_caller_identity" "current" {}

# Account-wide GitHub OIDC provider: read by ARN only, this root never creates one.
data "aws_iam_openid_connect_provider" "github" {
  arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
}
