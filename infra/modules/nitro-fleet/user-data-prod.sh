#!/bin/bash
# kaskad-nitro prod host bootstrap (launch-template user-data): host prep, relay
# plane, then the keyex enclaves — oracle CID 16 always, pontifex CID 17 when
# enable_pontifex. Each EIF is pinned by sha384 + PCR0 in this template; S3 is
# untrusted storage and no KMS is involved. The host is untrusted by design:
# relay scripts are unsigned, the enclave verifies every peer over RA-TLS.
# No secrets here; S3 and EC2 describe come from the instance role.
set -euxo pipefail
exec > >(tee -a /var/log/kaskad-init.log) 2>&1

dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel awscli \
  amazon-cloudwatch-agent jq socat python3 openssl
usermod -aG ne root

# Host logs -> ${log_group} (this region), one stream per file. Non-fatal.
CW_CFG=/opt/aws/amazon-cloudwatch-agent/etc/kaskad.json
jq -n --arg g "${log_group}" '{agent: {run_as_user: "root"}, logs: {logs_collected: {files: {collect_list:
  [$ARGS.positional[] | {file_path: "/var/log/kaskad-\(.).log", log_group_name: $g, log_stream_name: "{instance_id}/\(.)"}]}}}}' \
  --args init allocator-diag egress ratls pull-api pontifex-host genesis-capture oracle pontifex >"$${CW_CFG}"
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c "file:$${CW_CFG}" \
  || echo "WARN: cloudwatch agent did not start; logs stay local"

# Enclave allocator pool. Sized by terraform to cover every enclave this host
# will boot, else the second run-enclave has no CPUs/memory left to claim.
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
  aws s3 cp "$DIAG" "s3://${eif_bucket}/diag/$IID-allocator.log" --region "${artifact_region}" || true
  echo "FATAL allocator boot failed; diag on console + s3://${eif_bucket}/diag/$IID-allocator.log"
  exit 1
fi
set -e

# The bucket may live in another region (EU boots from us-east-1).
ARTIFACT_REGION=${artifact_region}
BUCKET=${eif_bucket}
KASKAD_DIR=/opt/kaskad
mkdir -p "$${KASKAD_DIR}" /etc/kaskad

# fetch_pinned <name> <sha384> <pcr0>: content-addressed fetch, then the file
# digest and the EIF's own PCR0 must both equal the pin. Any mismatch is fatal.
fetch_pinned() {
  local name="$1" sha="$2" pcr0="$3" eif="$${KASKAD_DIR}/$1.eif" got
  [[ "$${sha}" =~ ^[0-9a-f]{96}$ && "$${pcr0}" =~ ^[0-9a-f]{96}$ ]] \
    || { echo "FATAL: $${name} pin malformed"; exit 1; }
  aws s3 cp "s3://$${BUCKET}/eif/$${sha}.eif" "$${eif}" --region "$${ARTIFACT_REGION}"
  got=$(sha384sum "$${eif}" | awk '{print $1}')
  [ "$${got}" = "$${sha}" ] || { echo "FATAL: $${name} sha384 $${got} != pin $${sha}"; exit 1; }
  got=$(nitro-cli describe-eif --eif-path "$${eif}" | jq -r '.Measurements.PCR0')
  [ "$${got}" = "$${pcr0}" ] || { echo "FATAL: $${name} PCR0 $${got} != pin $${pcr0}"; exit 1; }
  echo "$${name} EIF matches pin: sha384=$${sha} PCR0=$${pcr0}"
}

ENCLAVE_DEBUG=${enclave_debug_mode}

# run_enclave <name> <cid> <cpu> <mem>. Console exists only in debug mode
# (prod enclaves refuse it with E44, so a prod console unit just crash-loops).
run_enclave() {
  local name="$1" cid="$2" cpu="$3" mem="$4"
  local out eid debug_args=()
  if [ "$${ENCLAVE_DEBUG}" = "true" ]; then debug_args=(--debug-mode); fi
  out=$(nitro-cli run-enclave \
    --eif-path "$${KASKAD_DIR}/$${name}.eif" \
    --enclave-cid "$${cid}" \
    --cpu-count "$${cpu}" \
    --memory "$${mem}" "$${debug_args[@]}")
  echo "$${out}" | tee "$${KASKAD_DIR}/$${name}-run.json"
  eid=$(echo "$${out}" | jq -r '.EnclaveID')
  echo "$${name} enclave: CID=$${cid} EnclaveID=$${eid}"
  [ "$${ENCLAVE_DEBUG}" = "true" ] || return 0
  cat > "/etc/systemd/system/kaskad-$${name}-console.service" <<SVC
[Unit]
Description=Kaskad $${name} enclave console
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/nitro-cli console --enclave-id $${eid}
Restart=no
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
aws s3 cp "s3://$${BUCKET}/host${eif_release_suffix}/http_connect_proxy.py" "$${KASKAD_DIR}/http_connect_proxy.py" --region "$${ARTIFACT_REGION}"
aws s3 cp "s3://$${BUCKET}/host${eif_release_suffix}/pontifex_host.py"      "$${KASKAD_DIR}/pontifex_host.py"      --region "$${ARTIFACT_REGION}"
aws s3 cp "s3://$${BUCKET}/host${eif_release_suffix}/pull_api.py"           "$${KASKAD_DIR}/pull_api.py"           --region "$${ARTIFACT_REGION}"
aws s3 cp "s3://$${BUCKET}/host${eif_release_suffix}/genesis_capture.py"    "$${KASKAD_DIR}/genesis_capture.py"    --region "$${ARTIFACT_REGION}"
chmod +x "$${KASKAD_DIR}"/*.py

# Enclaves boot inline below (tf-sized allocator). Front-ends (pull-api,
# pontifex-host) start after the enclaves; egress + RA-TLS relays start before.
for u in kaskad-egress-connect kaskad-egress-vsock kaskad-oracle-ratls \
         kaskad-pull-api kaskad-pontifex-host kaskad-genesis-capture; do
  aws s3 cp "s3://$${BUCKET}/host${eif_release_suffix}/systemd/$${u}.service" "/etc/systemd/system/$${u}.service" --region "$${ARTIFACT_REGION}"
done
aws s3 cp "s3://$${BUCKET}/host${eif_release_suffix}/systemd/kaskad-genesis-capture.timer" \
  /etc/systemd/system/kaskad-genesis-capture.timer --region "$${ARTIFACT_REGION}"
systemctl daemon-reload

# Public, non-secret host hints (untrusted — the enclave bakes its own
# trust-critical addresses into PCR0). Empty until go-live; the host config
# loop simply idles until they are set.
cat >/etc/kaskad/pull-api.env <<EOF
VPC_CIDR=${vpc_cidr}
EDGE_HOST=${edge_domain_name}
EOF
cat >/etc/kaskad/pontifex-host.env <<EOF
KASKAD_ORACLE_REGISTRY=${oracle_registry}
KASKAD_BRIDGE_ENTRY=${bridge_entry}
KASKAD_RH_RPCS=${rh_rpcs}
KASKAD_ASG_NAME=${asg_name}
KASKAD_PEER_ASGS=${peer_asgs}
KASKAD_AWS_REGION=${aws_region}
KASKAD_ARTIFACT_REGION=${artifact_region}
KASKAD_EIF_BUCKET=${eif_bucket}
PONTIFEX_HOST_PORT=8081
PONTIFEX_TRUSTED_PROXY_CIDRS=${vpc_cidr}
EOF
cat >/etc/kaskad/genesis-capture.env <<EOF
KASKAD_EIF_BUCKET=${eif_bucket}
KASKAD_AWS_REGION=${aws_region}
KASKAD_ARTIFACT_REGION=${artifact_region}
KASKAD_ORACLE_CID=16
KASKAD_CONTROL_PORT=5005
EOF

# Egress + RA-TLS relays MUST be up before the enclaves boot: the oracle pulls
# exchange prices over egress, and the bridge fetches k_bridge from the
# co-located oracle over egress -> oracle-ratls (TCP:8443 -> VSOCK CID16:5002).
systemctl enable --now kaskad-egress-connect.service kaskad-egress-vsock.service
systemctl enable --now kaskad-oracle-ratls.service

# Oracle first: the bridge's boot fetch of k_bridge needs the oracle's handover
# server already listening on the local VSOCK. ENABLE_PONTIFEX=false is the
# oracle-only host (the EU region, and US before a bridge release exists).
ENABLE_PONTIFEX=${enable_pontifex}

fetch_pinned oracle "${oracle_sha384}" "${oracle_pcr0}"
run_enclave oracle 16 ${oracle_cpu_count} ${oracle_memory_mib}

if [ "$${ENABLE_PONTIFEX}" = "true" ]; then
  fetch_pinned pontifex "${pontifex_sha384}" "${pontifex_pcr0}"
  run_enclave pontifex 17 ${pontifex_cpu_count} ${pontifex_memory_mib}
fi

# Refresh public attestations without restarting the enclave or rotating its key.
systemctl start --no-block kaskad-genesis-capture.service
systemctl enable --now kaskad-genesis-capture.timer

# Front-ends last: pull API (8080 -> CID16:5001) and pontifex host (8081 ->
# bridge VSOCK CID17:5004). Both retry until their enclave answers.
systemctl enable --now kaskad-pull-api.service
# Always on: this host also runs the configure loop that discovers sibling
# oracle instances and hands them to the enclave as RA-TLS peers. The bridge
# half of that loop is gated separately by an empty KASKAD_BRIDGE_ENTRY.
systemctl enable --now kaskad-pontifex-host.service

nitro-cli describe-enclaves | tee "$${KASKAD_DIR}/enclave-status.json"
echo "=== keyex enclaves running: oracle CID16, pontifex=$${ENABLE_PONTIFEX} + relay plane up ==="
