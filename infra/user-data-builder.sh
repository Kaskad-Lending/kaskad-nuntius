#!/bin/bash
# Builder EC2 user-data: clones repo, builds Docker + EIF, uploads to S3, self-stops
set -euo pipefail
exec > /var/log/kaskad-build.log 2>&1

INSTANCE_ID=$(ec2-metadata -i | cut -d' ' -f2)
echo "=== Kaskad Oracle Builder ==="
echo "Instance: $INSTANCE_ID"
echo "Timestamp: $(date -u)"

# ─── Get build commit from instance tags ─────────────
COMMIT=$(aws ec2 describe-tags \
  --filters "Name=resource-id,Values=$INSTANCE_ID" "Name=key,Values=BuildCommit" \
  --query 'Tags[0].Value' --output text --region ${aws_region})

if [ "$COMMIT" = "None" ] || [ -z "$COMMIT" ]; then
  echo "ERROR: No BuildCommit tag found. Stopping."
  aws ec2 stop-instances --instance-ids $INSTANCE_ID --region ${aws_region}
  exit 1
fi

echo "Building commit: $COMMIT"

# ─── Install dependencies ────────────────────────────
dnf install -y docker git aws-nitro-enclaves-cli
systemctl start docker

# ─── Clone & checkout ────────────────────────────────
rm -rf /tmp/build
git clone https://github.com/${github_org}/${github_repo}.git /tmp/build
cd /tmp/build
git checkout $COMMIT

# ─── Docker build ────────────────────────────────────
echo "Building Docker image..."
docker build -t kaskad-oracle:latest . 2>&1
echo "Docker build complete"

# ─── Build EIF ───────────────────────────────────────
echo "Building EIF..."
nitro-cli build-enclave \
  --docker-uri kaskad-oracle:latest \
  --output-file /tmp/oracle.eif \
  | tee /tmp/build-output.json

PCR0=$(python3 -c "import json; print(json.load(open('/tmp/build-output.json'))['Measurements']['PCR0'])")
echo "PCR0: $PCR0"

# ─── Upload to S3 ────────────────────────────────────
echo "Uploading to S3..."
aws s3 cp /tmp/oracle.eif s3://${eif_bucket}/latest.eif
aws s3 cp /tmp/build-output.json s3://${eif_bucket}/pcr0.json

# Tag with build metadata
aws s3api put-object-tagging \
  --bucket ${eif_bucket} \
  --key latest.eif \
  --tagging "TagSet=[{Key=Commit,Value=$COMMIT},{Key=PCR0,Value=$PCR0},{Key=BuildTime,Value=$(date -u +%Y%m%dT%H%M%SZ)}]"

echo "=== Build Complete ==="
echo "EIF: s3://${eif_bucket}/latest.eif"
echo "PCR0: $PCR0"
echo "Commit: $COMMIT"

# ─── Self-stop ───────────────────────────────────────
echo "Self-stopping..."
aws ec2 stop-instances --instance-ids $INSTANCE_ID --region ${aws_region}
