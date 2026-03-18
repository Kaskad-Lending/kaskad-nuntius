#!/bin/bash
# Prod EC2 user-data: pulls EIF from S3, starts VSOCK proxy + enclave
set -euo pipefail
exec > /var/log/kaskad-init.log 2>&1

echo "=== Kaskad Oracle Prod Init ==="
echo "Instance ID: $(ec2-metadata -i | cut -d' ' -f2)"
echo "Timestamp: $(date -u)"

# ─── Install dependencies ────────────────────────────
dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker python3-pip
pip3 install requests

# ─── Configure enclave allocator ─────────────────────
cat > /etc/nitro_enclaves/allocator.yaml << EOF
---
memory_mib: ${enclave_memory_mib}
cpu_count: ${enclave_cpu_count}
EOF

systemctl enable --now nitro-enclaves-allocator.service
systemctl enable --now docker

# Add ec2-user to groups
usermod -aG ne ec2-user
usermod -aG docker ec2-user

# ─── Pull EIF from S3 ────────────────────────────────
mkdir -p /opt/kaskad
aws s3 cp s3://${eif_bucket}/latest.eif /opt/kaskad/oracle.eif
aws s3 cp s3://${eif_bucket}/pcr0.json /opt/kaskad/pcr0.json || true

echo "EIF downloaded: $(ls -lh /opt/kaskad/oracle.eif)"

# ─── Create VSOCK proxy ──────────────────────────────
cat > /opt/kaskad/vsock_proxy.py << 'PROXY'
${vsock_proxy_script}
PROXY

cat > /etc/systemd/system/kaskad-vsock-proxy.service << 'SVC'
[Unit]
Description=Kaskad VSOCK Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/kaskad/vsock_proxy.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVC

systemctl enable --now kaskad-vsock-proxy.service

# ─── Run enclave ─────────────────────────────────────
nitro-cli run-enclave \
  --eif-path /opt/kaskad/oracle.eif \
  --cpu-count ${enclave_cpu_count} \
  --memory ${enclave_memory_mib} \
  | tee /opt/kaskad/enclave-run.json

# Log enclave status
nitro-cli describe-enclaves | tee /opt/kaskad/enclave-status.json

echo "=== Kaskad Oracle Prod Init Complete ==="
