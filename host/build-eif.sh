#!/bin/bash
# Reproducibly build both keyex EIFs on the Nitro builder, extract PCRs,
# sign the manifests with the release KMS key, publish to S3.
# Images: oracle (Dockerfile.oracle) CID 16, pontifex (Dockerfile.pontifex) CID 17.
# Manual: sudo EIF_BUCKET=... KMS_RELEASE_ALIAS=... AWS_REGION=us-east-1 host/build-eif.sh
# CI invokes this over SSM. S3 PutObject + kms:Sign come from the instance role.
set -euo pipefail

: "${EIF_BUCKET:?EIF_BUCKET required}"
: "${KMS_RELEASE_ALIAS:?KMS_RELEASE_ALIAS required}"
AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_REGION AWS_DEFAULT_REGION="$AWS_REGION"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
COMMIT="${COMMIT:-$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# name:dockerfile — CID is assigned at run-enclave (oracle 16, pontifex 17).
# Slice 5 owns the keyex oracle image content; slice 6 the kaskad-pontifex bin.
IMAGES=(
  "oracle:Dockerfile.oracle"
  "pontifex:Dockerfile.pontifex"
)

# Baked identity (public addresses/RPCs/chain-ids, no secrets): sourced here and
# passed per image as --build-arg; option_env! bakes them into PCR0 at compile
# time. Reproducible: PCR0 = f(source commit + this file). Override the path with
# EIF_CONFIG=... for a different network.
EIF_CONFIG="${EIF_CONFIG:-host/eif-config/robinhood-testnet.env}"
[ -f "$EIF_CONFIG" ] || { echo "FATAL: EIF_CONFIG $EIF_CONFIG missing" >&2; exit 1; }
# shellcheck disable=SC1090
. "$EIF_CONFIG"
echo "baked identity: $EIF_CONFIG"

# Per-image build args; *_REQ must be non-empty (mirrors from_baked() in Rust).
ORACLE_ARGS=(KEYEX_ORACLE_REGISTRY KEYEX_ORACLE_RH_RPCS KEYEX_ORACLE_OWNERS KEYEX_ORACLE_THRESHOLD KEYEX_ORACLE_CHAIN_ID KEYEX_ORACLE_VERSION KEYEX_ORACLE_ANCESTORS KEYEX_ORACLE_PEERS)
ORACLE_REQ=(KEYEX_ORACLE_REGISTRY KEYEX_ORACLE_RH_RPCS KEYEX_ORACLE_OWNERS KEYEX_ORACLE_THRESHOLD KEYEX_ORACLE_CHAIN_ID KEYEX_ORACLE_VERSION)
PONTIFEX_ARGS=(PONTIFEX_EXIT PONTIFEX_KSKD PONTIFEX_ENTRY PONTIFEX_CHAIN_ID PONTIFEX_IGRA_RPCS PONTIFEX_VERSION PONTIFEX_ANCESTOR_PCRS)
# PONTIFEX_ANCESTOR_PCRS is required but auto-filled from the oracle build below,
# so it need not be in the .env; the req check runs after that injection.
PONTIFEX_REQ=(PONTIFEX_EXIT PONTIFEX_KSKD PONTIFEX_ENTRY PONTIFEX_CHAIN_ID PONTIFEX_IGRA_RPCS PONTIFEX_ANCESTOR_PCRS)

# Set after the oracle image is built; injected as the bridge's parent-oracle
# allowlist so the bridge pins the oracle it accepts a child key from by PCR0.
ORACLE_PCR0=""

# retry N SLEEP CMD... — pipefail-safe: -e is off around the call so a
# non-zero rc is read here, not swallowed mid-pipeline before PIPESTATUS.
retry() {
  local n="$1" s="$2"; shift 2
  local i=0 rc=0
  while :; do
    set +e; "$@"; rc=$?; set -e
    [ "$rc" -eq 0 ] && return 0
    i=$((i + 1)); [ "$i" -ge "$n" ] && return "$rc"
    echo "retry $i/$n (rc=$rc): $*" >&2; sleep "$s"
  done
}

# sign_raw MSG OUT — release key, RAW/ECDSA_SHA_384; matches the host's
# `openssl dgst -sha384 -verify` at boot (run-enclaves.sh).
sign_raw() {
  retry 3 5 aws kms sign \
    --key-id "$KMS_RELEASE_ALIAS" \
    --message "fileb://$1" \
    --message-type RAW \
    --signing-algorithm ECDSA_SHA_384 \
    --output text --query Signature | base64 -d > "$2"
  [ -s "$2" ] || { echo "FATAL: empty signature for $1" >&2; exit 1; }
}

S3="s3://$EIF_BUCKET"

build_one() {
  local name="$1" dockerfile="$2"
  local tag="kaskad-$name:$COMMIT" eif="$WORK/$name.eif"

  [ -f "$dockerfile" ] || { echo "FATAL: $dockerfile missing" >&2; exit 1; }

  # Select this image's baked identity vars (nameref → the arrays above).
  local -n _args _req
  case "$name" in
    oracle)   _args=ORACLE_ARGS;   _req=ORACLE_REQ ;;
    pontifex) _args=PONTIFEX_ARGS; _req=PONTIFEX_REQ ;;
    *) echo "FATAL: no baked args for image $name" >&2; exit 1 ;;
  esac

  # The bridge pins its parent oracle by PCR0, known only after the oracle EIF is
  # built (oracle builds first). Inject it as the bridge's allowlist unless the
  # .env pins one explicitly. Reproducible: bridge PCR0 = f(source + config +
  # oracle PCR0) = f(source + config). Closes the accept-any-parent hole.
  if [ "$name" = pontifex ] && [ -z "${PONTIFEX_ANCESTOR_PCRS:-}" ]; then
    [ -n "$ORACLE_PCR0" ] || { echo "FATAL: oracle PCR0 unknown; oracle must build before pontifex" >&2; exit 1; }
    PONTIFEX_ANCESTOR_PCRS="$ORACLE_PCR0"
    echo "pontifex: parent-oracle PCR0 allowlist := $PONTIFEX_ANCESTOR_PCRS"
  fi

  local av
  for av in "${_req[@]}"; do
    [ -n "${!av:-}" ] || { echo "FATAL: $name: required baked var $av empty in $EIF_CONFIG" >&2; exit 1; }
  done
  local buildargs=()
  for av in "${_args[@]}"; do buildargs+=(--build-arg "$av=${!av:-}"); done

  echo "=== build $name ($dockerfile) ==="
  sudo docker build "${buildargs[@]}" -f "$dockerfile" -t "$tag" .
  sudo nitro-cli build-enclave --docker-uri "$tag" --output-file "$eif" \
    > "$WORK/$name.build.json"
  sudo chown "$(id -u):$(id -g)" "$eif"
  cat "$WORK/$name.build.json"

  # PCR0/1/2 straight from build-enclave JSON.
  local pcr0 pcr1 pcr2
  pcr0=$(jq -r '.Measurements.PCR0' "$WORK/$name.build.json")
  pcr1=$(jq -r '.Measurements.PCR1' "$WORK/$name.build.json")
  pcr2=$(jq -r '.Measurements.PCR2' "$WORK/$name.build.json")
  local v
  for v in "$pcr0" "$pcr1" "$pcr2"; do
    [[ "$v" =~ ^[0-9a-f]{96}$ ]] || { echo "FATAL: $name bad PCR: $v" >&2; exit 1; }
  done

  # Remember the oracle PCR0 so the pontifex build (built next) pins it as parent.
  [ "$name" = oracle ] && ORACLE_PCR0="$pcr0"

  # Manifests the host verifies + the compact PCR triple for slice 10.
  jq '.Measurements' "$WORK/$name.build.json" > "$WORK/$name.pcr0.json"
  sha384sum "$eif" | awk '{print $1}' > "$WORK/$name.eif.sha384"
  printf '{"PCR0":"%s","PCR1":"%s","PCR2":"%s"}\n' "$pcr0" "$pcr1" "$pcr2" \
    > "$WORK/$name.pcrs.json"

  sign_raw "$WORK/$name.eif.sha384" "$WORK/$name.eif.sha384.sig"
  sign_raw "$WORK/$name.pcr0.json"  "$WORK/$name.pcr0.json.sig"

  # Immutable staging by commit + the latest.* the host boot fetches.
  retry 3 5 aws s3 cp "$eif"                  "$S3/staging/$COMMIT/$name.eif"
  retry 3 5 aws s3 cp "$WORK/$name.pcr0.json" "$S3/staging/$COMMIT/$name.pcr0.json"
  retry 3 5 aws s3 cp "$WORK/$name.eif.sha384" "$S3/staging/$COMMIT/$name.eif.sha384"
  retry 3 5 aws s3 cp "$WORK/$name.pcrs.json" "$S3/staging/$COMMIT/$name.pcrs.json"

  retry 3 5 aws s3 cp "$eif"                     "$S3/$name/latest.eif"
  retry 3 5 aws s3 cp "$WORK/$name.eif.sha384"     "$S3/$name/latest.eif.sha384"
  retry 3 5 aws s3 cp "$WORK/$name.eif.sha384.sig" "$S3/$name/latest.eif.sha384.sig"
  retry 3 5 aws s3 cp "$WORK/$name.pcr0.json"      "$S3/$name/pcr0.json"
  retry 3 5 aws s3 cp "$WORK/$name.pcr0.json.sig"  "$S3/$name/pcr0.json.sig"

  # Reclaim the oracle build cache + image before pontifex builds, so two musl
  # release trees need not co-reside on the 30G builder volume. Cache-independent
  # (digest-pinned bases + --locked): pruning is PCR-neutral.
  sudo docker rmi -f "$tag" >/dev/null 2>&1 || true
  sudo docker builder prune -af >/dev/null 2>&1 || true

  echo "$name PCR0=$pcr0"
}

# publish_host_bundle — copy the host relay plane to S3 so the prod launch
# template can fetch it at boot. Untrusted: no signature (a compromised host can
# only drop/delay bytes — TLS to RPCs and RA-TLS to peers both terminate inside
# the enclave; only the EIFs are release-signed).
publish_host_bundle() {
  echo "=== publish host bundle ==="
  retry 3 5 aws s3 cp host/http_connect_proxy.py "$S3/host/http_connect_proxy.py"
  retry 3 5 aws s3 cp host/pontifex_host.py      "$S3/host/pontifex_host.py"
  retry 3 5 aws s3 cp host/genesis_capture.py    "$S3/host/genesis_capture.py"
  retry 3 5 aws s3 cp enclave/pull_api.py        "$S3/host/pull_api.py"
  retry 3 5 aws s3 cp --recursive host/systemd/  "$S3/host/systemd/"
  echo "host bundle published to $S3/host/"
}

# Run the whole build piped to tee so the full transcript — not just SSM's
# truncated 2500-char tail — lands in S3 on success or failure. The pipeline
# barrier makes tee flush before the upload (no lost-tail race), and
# PIPESTATUS[0] carries the real build rc past the `| tee`.
BUILD_LOG="$(mktemp /tmp/build-eif-XXXXXX.log)"
# -e off around the pipeline so a failing build does not abort before the rc is
# read and the log is uploaded; the inner group keeps its inherited -e and fails
# fast, so PIPESTATUS[0] still carries the real build rc.
set +e
{
  for entry in "${IMAGES[@]}"; do
    build_one "${entry%%:*}" "${entry#*:}"
  done

  publish_host_bundle

  echo "=== keyex EIFs built + signed + published (commit $COMMIT) ==="
} 2>&1 | tee "$BUILD_LOG"
BUILD_RC=${PIPESTATUS[0]}
set -e
aws s3 cp "$BUILD_LOG" "$S3/builds/$COMMIT/build.log" >/dev/null 2>&1 || true
rm -f "$BUILD_LOG"
echo "build log: $S3/builds/$COMMIT/build.log (rc=$BUILD_RC)"
exit "$BUILD_RC"
