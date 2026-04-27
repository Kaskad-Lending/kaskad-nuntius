#!/bin/bash
# Prod EC2 user-data: pulls EIF from S3, starts VSOCK proxy + enclave + pull API + logging
set -euo pipefail
exec > /var/log/kaskad-init.log 2>&1

echo "=== Kaskad Oracle Prod Init ==="
echo "Instance ID: $(ec2-metadata -i | cut -d' ' -f2)"
echo "Timestamp: $(date -u)"

# ─── Install dependencies ────────────────────────────
dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker python3 amazon-cloudwatch-agent jq openssl
dnf install -y socat || echo "WARN: socat not in dnf, will install from source if needed"

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

# ─── Pull EIF + signed manifests from S3 ─────────────
mkdir -p /opt/kaskad

# Fetch the release pubkey once at boot. Verification afterwards is
# pure-local openssl — no per-request KMS round-trip.
aws kms get-public-key \
  --key-id alias/kaskad-oracle-release \
  --query PublicKey --output text \
  | base64 -d > /opt/kaskad/release_pubkey.der
openssl pkey -pubin -inform DER -in /opt/kaskad/release_pubkey.der \
  -outform PEM -out /opt/kaskad/release_pubkey.pem
echo "Release pubkey fetched: $(ls -l /opt/kaskad/release_pubkey.pem)"

# Pull EIF + 4 signed manifests. `set -euo pipefail` at the top of the
# script means any `aws s3 cp` failure exits the boot non-zero — there
# is no migration-mode fallback any more.
aws s3 cp s3://${eif_bucket}/latest.eif               /opt/kaskad/oracle.eif
aws s3 cp s3://${eif_bucket}/latest.eif.sha384        /opt/kaskad/oracle.eif.sha384
aws s3 cp s3://${eif_bucket}/latest.eif.sha384.sig    /opt/kaskad/oracle.eif.sha384.sig
aws s3 cp s3://${eif_bucket}/pcr0.json                /opt/kaskad/pcr0.json
aws s3 cp s3://${eif_bucket}/pcr0.json.sig            /opt/kaskad/pcr0.json.sig
echo "EIF + manifests downloaded: $(ls -lh /opt/kaskad/oracle.eif)"

# 1) Verify the signature on the SHA-384 manifest itself.
openssl dgst -sha384 -verify /opt/kaskad/release_pubkey.pem \
  -signature /opt/kaskad/oracle.eif.sha384.sig \
  /opt/kaskad/oracle.eif.sha384 \
  || { echo "FATAL: oracle.eif.sha384 signature invalid"; exit 1; }

# 2) Verify the EIF on disk hashes to the signed digest.
ACTUAL_SHA=$(sha384sum /opt/kaskad/oracle.eif | awk '{print $1}')
EXPECTED_SHA=$(cat /opt/kaskad/oracle.eif.sha384)
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "FATAL: EIF sha384 mismatch: actual=$ACTUAL_SHA expected=$EXPECTED_SHA"
  exit 1
fi

# 3) Verify the signature on the PCR0 manifest.
openssl dgst -sha384 -verify /opt/kaskad/release_pubkey.pem \
  -signature /opt/kaskad/pcr0.json.sig \
  /opt/kaskad/pcr0.json \
  || { echo "FATAL: pcr0.json signature invalid"; exit 1; }

# 4) Verify the EIF's actual PCR0 matches the signed manifest. Belt +
#    braces against (a) a sha384-colliding-but-distinct EIF (infeasible
#    under SHA-384, but cheap to check) and (b) a manifest pointing at
#    a PCR0 the local EIF doesn't actually produce.
EXPECTED_PCR0=$(jq -r '.PCR0' /opt/kaskad/pcr0.json)
ACTUAL_PCR0=$(nitro-cli describe-eif --eif-path /opt/kaskad/oracle.eif \
  | jq -r '.Measurements.PCR0')
if [ "$EXPECTED_PCR0" != "$ACTUAL_PCR0" ]; then
  echo "FATAL: PCR0 mismatch: expected=$EXPECTED_PCR0 actual=$ACTUAL_PCR0"
  exit 1
fi

echo "EIF integrity verified (sha384 + PCR0 signed by release KMS key)"

# ─── Create HTTP CONNECT proxy (Python, stdlib only) ───
cat > /opt/kaskad/http_connect_proxy.py << 'CONNECTPROXY'
"""Minimal HTTP CONNECT proxy using only Python stdlib.
Listens on 127.0.0.1:8888.  The enclave's socat bridges VSOCK:5000 → this.
reqwest inside the enclave does HTTP CONNECT through this to reach exchanges via TLS.
"""
import socket, threading, select, sys

LISTEN_ADDR = ("127.0.0.1", 8888)

def relay(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass

def handle_client(client_sock):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = client_sock.recv(4096)
            if not chunk:
                client_sock.close()
                return
            data += chunk

        first_line = data.split(b"\r\n")[0].decode()
        parts = first_line.split()
        if len(parts) < 3 or parts[0] != "CONNECT":
            client_sock.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            client_sock.close()
            return

        host_port = parts[1]
        if ":" in host_port:
            host, port = host_port.rsplit(":", 1)
            port = int(port)
        else:
            host, port = host_port, 443

        remote = socket.create_connection((host, port), timeout=10)
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        t1 = threading.Thread(target=relay, args=(client_sock, remote), daemon=True)
        t2 = threading.Thread(target=relay, args=(remote, client_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except Exception as e:
        print(f"[connect-proxy] error: {e}", file=sys.stderr)
        try: client_sock.close()
        except: pass

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN_ADDR)
    srv.listen(128)
    print(f"[connect-proxy] Listening on {LISTEN_ADDR}", flush=True)
    while True:
        client, addr = srv.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    main()
CONNECTPROXY

cat > /etc/systemd/system/kaskad-connect-proxy.service << 'SVC'
[Unit]
Description=Kaskad HTTP CONNECT Proxy (stdlib Python)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/kaskad/http_connect_proxy.py
Restart=always
RestartSec=5
StandardOutput=file:/var/log/kaskad-vsock-proxy.log
StandardError=file:/var/log/kaskad-vsock-proxy.log

[Install]
WantedBy=multi-user.target
SVC

systemctl enable --now kaskad-connect-proxy.service

# ─── VSOCK-to-TCP bridge: enclave VSOCK:5000 → local TCP:8888 ───
cat > /etc/systemd/system/kaskad-vsock-proxy.service << 'SVC'
[Unit]
Description=Kaskad VSOCK to HTTP CONNECT Bridge (outbound)
After=network.target kaskad-connect-proxy.service

[Service]
Type=simple
ExecStart=/usr/bin/socat VSOCK-LISTEN:5000,fork,reuseaddr TCP:127.0.0.1:8888
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
