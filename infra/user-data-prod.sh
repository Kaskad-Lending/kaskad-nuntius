#!/bin/bash
# Prod EC2 user-data: pulls EIF from S3, starts VSOCK proxy + enclave + pull API + logging
set -euo pipefail
exec > /var/log/kaskad-init.log 2>&1

echo "=== Kaskad Oracle Prod Init ==="
echo "Instance ID: $(ec2-metadata -i | cut -d' ' -f2)"
echo "Timestamp: $(date -u)"

# ─── Install dependencies ────────────────────────────
dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker python3 amazon-cloudwatch-agent

# ─── Configure enclave allocator ─────────────────────
cat > /etc/nitro_enclaves/allocator.yaml << EOF
---
memory_mib: ${enclave_memory_mib}
cpu_count: ${enclave_cpu_count}
EOF

systemctl enable --now nitro-enclaves-allocator.service
systemctl enable --now docker

usermod -aG ne ec2-user
usermod -aG docker ec2-user

# ─── Configure CloudWatch Agent ──────────────────────
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'CW_CONFIG'
{
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/kaskad-init.log",
            "log_group_name": "/kaskad/oracle",
            "log_stream_name": "{instance_id}/init"
          },
          {
            "file_path": "/var/log/kaskad-enclave.log",
            "log_group_name": "/kaskad/oracle",
            "log_stream_name": "{instance_id}/enclave"
          },
          {
            "file_path": "/var/log/kaskad-pull-api.log",
            "log_group_name": "/kaskad/oracle",
            "log_stream_name": "{instance_id}/pull-api"
          },
          {
            "file_path": "/var/log/kaskad-vsock-proxy.log",
            "log_group_name": "/kaskad/oracle",
            "log_stream_name": "{instance_id}/vsock-proxy"
          }
        ]
      }
    }
  }
}
CW_CONFIG

systemctl enable --now amazon-cloudwatch-agent

# ─── Pull EIF from S3 ────────────────────────────────
mkdir -p /opt/kaskad
aws s3 cp s3://${eif_bucket}/latest.eif /opt/kaskad/oracle.eif
aws s3 cp s3://${eif_bucket}/pcr0.json /opt/kaskad/pcr0.json || true

echo "EIF downloaded: $(ls -lh /opt/kaskad/oracle.eif)"

# ─── Create VSOCK proxy (outbound: enclave → internet) ───
cat > /opt/kaskad/vsock_proxy.py << 'PROXY'
${vsock_proxy_script}
PROXY

cat > /etc/systemd/system/kaskad-vsock-proxy.service << 'SVC'
[Unit]
Description=Kaskad VSOCK Proxy (outbound)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/kaskad/vsock_proxy.py
Restart=always
RestartSec=5
StandardOutput=file:/var/log/kaskad-vsock-proxy.log
StandardError=file:/var/log/kaskad-vsock-proxy.log

[Install]
WantedBy=multi-user.target
SVC

systemctl enable --now kaskad-vsock-proxy.service

# ─── Create Pull API (inbound: internet → enclave) ───
cat > /opt/kaskad/pull_api.py << 'PULLAPI'
${pull_api_script}
PULLAPI

cat > /etc/systemd/system/kaskad-pull-api.service << 'SVC'
[Unit]
Description=Kaskad Pull API (HTTP → VSOCK)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/kaskad/pull_api.py 8080
Restart=always
RestartSec=5
StandardOutput=file:/var/log/kaskad-pull-api.log
StandardError=file:/var/log/kaskad-pull-api.log

[Install]
WantedBy=multi-user.target
SVC

systemctl enable --now kaskad-pull-api.service

# ─── Run enclave ─────────────────────────────────────
ENCLAVE_OUTPUT=$(nitro-cli run-enclave \
  --eif-path /opt/kaskad/oracle.eif \
  --cpu-count ${enclave_cpu_count} \
  --memory ${enclave_memory_mib})

echo "$ENCLAVE_OUTPUT" | tee /opt/kaskad/enclave-run.json

ENCLAVE_ID=$(echo "$ENCLAVE_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['EnclaveID'])" 2>/dev/null || echo "unknown")
echo "Enclave ID: $ENCLAVE_ID"

# ─── Enclave console logger ─────────────────────────
cat > /etc/systemd/system/kaskad-enclave-console.service << SVC
[Unit]
Description=Kaskad Enclave Console Logger
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/nitro-cli console --enclave-id $ENCLAVE_ID
Restart=always
RestartSec=10
StandardOutput=file:/var/log/kaskad-enclave.log
StandardError=file:/var/log/kaskad-enclave.log

[Install]
WantedBy=multi-user.target
SVC

systemctl enable --now kaskad-enclave-console.service

# Log enclave status
nitro-cli describe-enclaves | tee /opt/kaskad/enclave-status.json

echo "=== Kaskad Oracle Prod Init Complete ==="
echo "Services: vsock-proxy, pull-api, enclave-console, cloudwatch-agent"
echo "Pull API: http://localhost:8080/prices"
