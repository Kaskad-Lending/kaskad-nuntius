#!/bin/bash
# kaskad-nitro-us prod host bootstrap (launch-template user-data). Host prep +
# relay plane, then fetch + release-signature-verify + run BOTH keyex enclaves:
# oracle CID 16 (price + keyex genesis) and pontifex bridge CID 17 (fetches
# k_bridge from the co-located oracle over the egress -> oracle-ratls path).
# The host is untrusted: relay scripts carry no signature (the enclave verifies
# every peer over RA-TLS, every burn on-chain, every image by attestation); only
# the EIFs are release-signed. No key sealing — keyex custody is the enclave
# fleet. No secrets in this script; S3 GetObject + KMS GetPublicKey + EC2/S3
# describe come from the instance role.
set -euxo pipefail
exec > >(tee -a /var/log/kaskad-init.log) 2>&1

dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel awscli \
  amazon-cloudwatch-agent jq socat python3 openssl
usermod -aG ne root

# Enclave allocator pool. Sized to cover BOTH enclaves at once (oracle +
# pontifex), else the second run-enclave has no CPUs/memory left to claim.
# The `---` doc-start and memory_mib-first order mirror the live oracle's
# proven allocator.yaml; without `---` the allocator parses memory_mib as
# missing and refuses to start.
cat >/etc/nitro_enclaves/allocator.yaml <<EOF
---
memory_mib: ${allocator_memory_mib}
cpu_count: ${allocator_cpu_count}
EOF
# The allocator fails fast on a bad host (CPU/hugepage state) and the ASG EC2
# health check would still report InService, hiding a dead app. On failure dump
# the real error to the console (get-console-output) and S3, then abort loudly.
set +e
systemctl enable --now nitro-enclaves-allocator.service
alloc_rc=$?
if [ "$alloc_rc" -ne 0 ]; then
  IID=$(ec2-metadata -i 2>/dev/null | cut -d' ' -f2)
  DIAG=/var/log/kaskad-allocator-diag.log
  {
    echo "=== allocator failed rc=$alloc_rc iid=$IID $(date -u) ==="
    echo "--- allocator.yaml (cat -A) ---";    cat -A /etc/nitro_enclaves/allocator.yaml
    echo "--- allocator.yaml (od -c) ---";     od -c /etc/nitro_enclaves/allocator.yaml
    echo "--- systemctl cat (ExecStart) ---"; systemctl cat nitro-enclaves-allocator.service
    echo "--- systemctl status ---";          systemctl status nitro-enclaves-allocator.service --no-pager -l
    echo "--- journalctl -xeu ---";           journalctl -xeu nitro-enclaves-allocator.service --no-pager
    echo "--- dmesg nitro/huge/cpu ---";      dmesg | grep -iE 'nitro|enclave|huge|cpu' | tail -50
    echo "--- /proc/meminfo huge ---";        grep -i huge /proc/meminfo
    for h in /sys/kernel/mm/hugepages/*; do
      echo "hugepages $h nr=$(cat $h/nr_hugepages 2>/dev/null) free=$(cat $h/free_hugepages 2>/dev/null)"
    done
    echo "--- ne_cpus param ---";             cat /sys/module/nitro_enclaves/parameters/ne_cpus 2>/dev/null
    echo "--- /dev/nitro_enclaves ---";       ls -la /dev/nitro_enclaves 2>/dev/null
    echo "--- lsmod nitro ---";               lsmod | grep -i nitro
    echo "--- lscpu ---";                     lscpu
    echo "--- nproc ---";                     nproc
  } 2>&1 | tee "$DIAG"
  aws s3 cp "$DIAG" "s3://${eif_bucket}/diag/$IID-allocator.log" --region "${aws_region}" || true
  echo "FATAL allocator boot failed; diag on console + s3://${eif_bucket}/diag/$IID-allocator.log"
  exit 1
fi
set -e

REGION=${aws_region}
BUCKET=${eif_bucket}
RELEASE_ALIAS=${kms_release_alias}
KASKAD_DIR=/opt/kaskad
mkdir -p "$${KASKAD_DIR}" /etc/kaskad

# Release pubkey → PEM once; every EIF is verified locally against it (no
# per-file KMS call). The key is public.
aws kms get-public-key --key-id "$${RELEASE_ALIAS}" --region "$${REGION}" \
  --query PublicKey --output text | base64 -d > "$${KASKAD_DIR}/release_pubkey.der"
openssl pkey -pubin -inform DER -in "$${KASKAD_DIR}/release_pubkey.der" \
  -outform PEM -out "$${KASKAD_DIR}/release_pubkey.pem"

# fetch_and_verify <s3-prefix> <local-name>. The release key RAW/ECDSA_SHA_384-
# signs the sha384 DIGEST file (build-eif.sh sign_raw), so verify the signature
# over that file, then match the digest to the EIF, then the signed PCR0 to the
# EIF's own measurement. Any mismatch is fatal — the host never runs an
# unattested image.
fetch_and_verify() {
  local prefix="$1" name="$2" d="$${KASKAD_DIR}"
  aws s3 cp "s3://$${BUCKET}/$${prefix}/latest.eif"            "$${d}/$${name}.eif"            --region "$${REGION}"
  aws s3 cp "s3://$${BUCKET}/$${prefix}/latest.eif.sha384"     "$${d}/$${name}.eif.sha384"     --region "$${REGION}"
  aws s3 cp "s3://$${BUCKET}/$${prefix}/latest.eif.sha384.sig" "$${d}/$${name}.eif.sha384.sig" --region "$${REGION}"
  aws s3 cp "s3://$${BUCKET}/$${prefix}/pcr0.json"             "$${d}/$${name}.pcr0.json"      --region "$${REGION}"
  aws s3 cp "s3://$${BUCKET}/$${prefix}/pcr0.json.sig"         "$${d}/$${name}.pcr0.json.sig"  --region "$${REGION}"

  openssl dgst -sha384 -verify "$${d}/release_pubkey.pem" \
    -signature "$${d}/$${name}.eif.sha384.sig" "$${d}/$${name}.eif.sha384" \
    || { echo "FATAL: $${name} eif.sha384 signature invalid"; exit 1; }
  local actual expected
  actual=$(sha384sum "$${d}/$${name}.eif" | awk '{print $1}')
  expected=$(cat "$${d}/$${name}.eif.sha384")
  [ "$${actual}" = "$${expected}" ] || { echo "FATAL: $${name} sha384 mismatch"; exit 1; }
  openssl dgst -sha384 -verify "$${d}/release_pubkey.pem" \
    -signature "$${d}/$${name}.pcr0.json.sig" "$${d}/$${name}.pcr0.json" \
    || { echo "FATAL: $${name} pcr0 signature invalid"; exit 1; }
  local ep ap
  ep=$(jq -r '.PCR0' "$${d}/$${name}.pcr0.json")
  ap=$(nitro-cli describe-eif --eif-path "$${d}/$${name}.eif" | jq -r '.Measurements.PCR0')
  [ "$${ep}" = "$${ap}" ] || { echo "FATAL: $${name} PCR0 mismatch ($${ep} != $${ap})"; exit 1; }
  echo "$${name} EIF verified (sha384 + PCR0 signed)"
}

# run_enclave <name> <cid> <cpu> <mem>. Attaches a console logger unit so the
# enclave's stdout lands in /var/log for CloudWatch.
run_enclave() {
  local name="$1" cid="$2" cpu="$3" mem="$4"
  local out eid
  out=$(nitro-cli run-enclave \
    --eif-path "$${KASKAD_DIR}/$${name}.eif" \
    --enclave-cid "$${cid}" \
    --cpu-count "$${cpu}" \
    --memory "$${mem}")
  echo "$${out}" | tee "$${KASKAD_DIR}/$${name}-run.json"
  eid=$(echo "$${out}" | jq -r '.EnclaveID')
  echo "$${name} enclave: CID=$${cid} EnclaveID=$${eid}"
  cat > "/etc/systemd/system/kaskad-$${name}-console.service" <<SVC
[Unit]
Description=Kaskad $${name} enclave console
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/nitro-cli console --enclave-id $${eid}
Restart=always
RestartSec=10
StandardOutput=file:/var/log/kaskad-$${name}.log
StandardError=file:/var/log/kaskad-$${name}.log

[Install]
WantedBy=multi-user.target
SVC
  systemctl enable --now "kaskad-$${name}-console.service"
}

# ── Host relay plane ────────────────────────────────────────────────
# Untrusted host scripts + systemd units from S3 (published by build-eif.sh).
# No signature check: a compromised host can only drop/delay bytes, never forge
# (TLS to RPCs and RA-TLS to peers both terminate INSIDE the enclave boundary).
aws s3 cp "s3://$${BUCKET}/host/http_connect_proxy.py" "$${KASKAD_DIR}/http_connect_proxy.py" --region "$${REGION}"
aws s3 cp "s3://$${BUCKET}/host/pontifex_host.py"      "$${KASKAD_DIR}/pontifex_host.py"      --region "$${REGION}"
aws s3 cp "s3://$${BUCKET}/host/pull_api.py"           "$${KASKAD_DIR}/pull_api.py"           --region "$${REGION}"
aws s3 cp "s3://$${BUCKET}/host/genesis_capture.py"    "$${KASKAD_DIR}/genesis_capture.py"    --region "$${REGION}"
chmod +x "$${KASKAD_DIR}"/*.py

# Design A: enclaves boot inline below (tf-sized allocator), so kaskad-enclaves
# .service is deliberately NOT installed. Front-ends (pull-api, pontifex-host)
# start after the enclaves; egress + RA-TLS relays start before.
for u in kaskad-egress-connect kaskad-egress-vsock kaskad-oracle-ratls \
         kaskad-pull-api kaskad-pontifex-host kaskad-genesis-capture; do
  aws s3 cp "s3://$${BUCKET}/host/systemd/$${u}.service" "/etc/systemd/system/$${u}.service" --region "$${REGION}"
done
aws s3 cp "s3://$${BUCKET}/host/systemd/kaskad-genesis-capture.timer" \
  /etc/systemd/system/kaskad-genesis-capture.timer --region "$${REGION}"
systemctl daemon-reload

# Public, non-secret host hints (untrusted — the enclave bakes its own
# trust-critical addresses into PCR0). Empty until go-live; the host config
# loop simply idles until they are set.
cat >/etc/kaskad/pull-api.env <<EOF
VPC_CIDR=${vpc_cidr}
EOF
cat >/etc/kaskad/pontifex-host.env <<EOF
KASKAD_ORACLE_REGISTRY=${oracle_registry}
KASKAD_BRIDGE_ENTRY=${bridge_entry}
KASKAD_RH_RPCS=${rh_rpcs}
KASKAD_ASG_NAME=${asg_name}
KASKAD_AWS_REGION=${aws_region}
KASKAD_EIF_BUCKET=${eif_bucket}
PONTIFEX_HOST_PORT=8081
PONTIFEX_TRUSTED_PROXY_CIDRS=${vpc_cidr}
EOF
cat >/etc/kaskad/genesis-capture.env <<EOF
KASKAD_EIF_BUCKET=${eif_bucket}
KASKAD_AWS_REGION=${aws_region}
KASKAD_ORACLE_CID=16
KASKAD_CONTROL_PORT=5005
EOF

# Egress + RA-TLS relays MUST be up before the enclaves boot: the oracle pulls
# exchange prices over egress, and the bridge fetches k_bridge from the
# co-located oracle over egress -> oracle-ratls (TCP:8443 -> VSOCK CID16:5002).
systemctl enable --now kaskad-egress-connect.service kaskad-egress-vsock.service
systemctl enable --now kaskad-oracle-ratls.service

fetch_and_verify oracle   oracle
fetch_and_verify pontifex pontifex

# Oracle first: the bridge's boot fetch of k_bridge needs the oracle's handover
# server already listening on the local VSOCK.
run_enclave oracle   16 ${oracle_cpu_count}   ${oracle_memory_mib}
run_enclave pontifex 17 ${pontifex_cpu_count} ${pontifex_memory_mib}

# Refresh public attestations without restarting the enclave or rotating its key.
systemctl start --no-block kaskad-genesis-capture.service
systemctl enable --now kaskad-genesis-capture.timer

# Front-ends last: pull API (8080 -> CID16:5001) and pontifex host (8081 ->
# bridge VSOCK CID17:5004). Both retry until their enclave answers.
systemctl enable --now kaskad-pull-api.service
systemctl enable --now kaskad-pontifex-host.service

nitro-cli describe-enclaves | tee "$${KASKAD_DIR}/enclave-status.json"
echo "=== keyex enclaves running: oracle CID16, pontifex CID17 + relay plane up ==="
