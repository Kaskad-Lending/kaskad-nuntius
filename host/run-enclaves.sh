#!/bin/bash
# Verify + launch both keyex enclaves, then start console loggers.
# Oracle: CID 16, 4 vCPU / 1024 MiB. Pontifex: CID 17, 2 vCPU / 512 MiB.
# EIFs + signed manifests are fetched under oracle/ and pontifex/ prefixes,
# same release-key checks as the live oracle. No secrets live in this script;
# S3/KMS access is the instance role.
set -euo pipefail
exec > >(tee -a /var/log/kaskad-init.log) 2>&1

: "${EIF_BUCKET:?EIF_BUCKET required}"
: "${KMS_RELEASE_ALIAS:?KMS_RELEASE_ALIAS required}"
KASKAD_DIR=/opt/kaskad
mkdir -p "$KASKAD_DIR"

# Release pubkey (local openssl verification afterwards, no per-file KMS call).
aws kms get-public-key --key-id "$KMS_RELEASE_ALIAS" \
  --query PublicKey --output text | base64 -d > "$KASKAD_DIR/release_pubkey.der"
openssl pkey -pubin -inform DER -in "$KASKAD_DIR/release_pubkey.der" \
  -outform PEM -out "$KASKAD_DIR/release_pubkey.pem"

# fetch_and_verify <s3-prefix> <local-name>
fetch_and_verify() {
  local prefix="$1" name="$2" d="$KASKAD_DIR"
  aws s3 cp "s3://$EIF_BUCKET/$prefix/latest.eif"            "$d/$name.eif"
  aws s3 cp "s3://$EIF_BUCKET/$prefix/latest.eif.sha384"     "$d/$name.eif.sha384"
  aws s3 cp "s3://$EIF_BUCKET/$prefix/latest.eif.sha384.sig" "$d/$name.eif.sha384.sig"
  aws s3 cp "s3://$EIF_BUCKET/$prefix/pcr0.json"             "$d/$name.pcr0.json"
  aws s3 cp "s3://$EIF_BUCKET/$prefix/pcr0.json.sig"         "$d/$name.pcr0.json.sig"

  openssl dgst -sha384 -verify "$d/release_pubkey.pem" \
    -signature "$d/$name.eif.sha384.sig" "$d/$name.eif.sha384" \
    || { echo "FATAL: $name eif.sha384 signature invalid"; exit 1; }
  local actual expected
  actual=$(sha384sum "$d/$name.eif" | awk '{print $1}')
  expected=$(cat "$d/$name.eif.sha384")
  [ "$actual" = "$expected" ] || { echo "FATAL: $name sha384 mismatch"; exit 1; }
  openssl dgst -sha384 -verify "$d/release_pubkey.pem" \
    -signature "$d/$name.pcr0.json.sig" "$d/$name.pcr0.json" \
    || { echo "FATAL: $name pcr0 signature invalid"; exit 1; }
  local ep ap
  ep=$(jq -r '.PCR0' "$d/$name.pcr0.json")
  ap=$(nitro-cli describe-eif --eif-path "$d/$name.eif" | jq -r '.Measurements.PCR0')
  [ "$ep" = "$ap" ] || { echo "FATAL: $name PCR0 mismatch ($ep != $ap)"; exit 1; }
  echo "$name EIF verified (sha384 + PCR0 signed)"
}

# run_enclave <name> <cid> <cpu> <mem>
run_enclave() {
  local name="$1" cid="$2" cpu="$3" mem="$4"
  local out
  out=$(nitro-cli run-enclave \
    --eif-path "$KASKAD_DIR/$name.eif" \
    --enclave-cid "$cid" \
    --cpu-count "$cpu" \
    --memory "$mem")
  echo "$out" | tee "$KASKAD_DIR/$name-run.json"
  local eid
  eid=$(echo "$out" | jq -r '.EnclaveID')
  echo "$name enclave: CID=$cid EnclaveID=$eid"
  # Console logger unit, per image.
  cat > "/etc/systemd/system/kaskad-$name-console.service" << SVC
[Unit]
Description=Kaskad $name enclave console
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/nitro-cli console --enclave-id $eid
Restart=always
RestartSec=10
StandardOutput=file:/var/log/kaskad-$name.log
StandardError=file:/var/log/kaskad-$name.log

[Install]
WantedBy=multi-user.target
SVC
  systemctl enable --now "kaskad-$name-console.service"
}

fetch_and_verify oracle oracle
fetch_and_verify pontifex pontifex

run_enclave oracle   16 4 1024
run_enclave pontifex 17 2 512

nitro-cli describe-enclaves | tee "$KASKAD_DIR/enclave-status.json"
echo "=== keyex enclaves running: oracle CID16, pontifex CID17 ==="
