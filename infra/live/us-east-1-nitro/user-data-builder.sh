#!/bin/bash
# kaskad-nitro-us builder. CI starts it via SSM, builds + signs the EIF,
# uploads to S3, then stops itself. No inbound access.
set -euxo pipefail

dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel awscli docker git
systemctl enable --now docker

REGION=${aws_region}
BUCKET=${eif_bucket}
ORG=${github_org}
REPO=${github_repo}

echo "builder ready: $${ORG}/$${REPO} -> s3://$${BUCKET} ($${REGION})"
# CI drives the build/sign/upload over SSM SendCommand from here.
