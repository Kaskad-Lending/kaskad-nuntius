#!/bin/bash
# Reproducibly build the keyex EIFs on the Nitro builder, publish each one
# content-addressed as eif/<sha384>.eif and print its pin for
# infra/live/eif-release.json. Nothing is signed: the pin in git is the trust root.
# Images: oracle (Dockerfile.oracle) CID 16, pontifex (Dockerfile.pontifex) CID 17.
# Manual: sudo EIF_BUCKET=... AWS_REGION=us-east-1 host/build-eif.sh
set -euo pipefail

: "${EIF_BUCKET:?EIF_BUCKET required}"
AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_REGION AWS_DEFAULT_REGION="$AWS_REGION"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
COMMIT="${COMMIT:-$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)}"

# Every file in the enclave rootfs is stamped with this one mtime: nitro-cli
# stores mtimes in the application CPIO, so a wall-clock time would make PCR2
# — and with it PCR0 — unreproducible. The Dockerfiles require the build-arg.
SOURCE_DATE_EPOCH=1700000000

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# name:dockerfile — CID is assigned at run-enclave (oracle 16, pontifex 17).
# Slice 5 owns the keyex oracle image content; slice 6 the kaskad-pontifex bin.
IMAGES=(
  "oracle:Dockerfile.oracle"
  "pontifex:Dockerfile.pontifex"
)

# EIF_IMAGES=oracle builds a subset, in the order listed above. The bridge pins
# the oracle's PCR0, so "pontifex" alone needs PONTIFEX_ANCESTOR_PCRS set in the
# config; dropping "oracle" from a full run is otherwise an error.
if [ -n "${EIF_IMAGES:-}" ]; then
  _want=",$(echo "$EIF_IMAGES" | tr ' ' ',')," _keep=()
  for entry in "${IMAGES[@]}"; do
    case "$_want" in *",${entry%%:*},"*) _keep+=("$entry") ;; esac
  done
  [ ${#_keep[@]} -gt 0 ] || { echo "FATAL: EIF_IMAGES='$EIF_IMAGES' matches no image" >&2; exit 1; }
  IMAGES=("${_keep[@]}")
  echo "image subset: ${IMAGES[*]%%:*}"
fi

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
ORACLE_ARGS=(KEYEX_ORACLE_REGISTRY KEYEX_ORACLE_RH_RPCS KEYEX_ORACLE_SAFE KEYEX_ORACLE_OWNERS KEYEX_ORACLE_THRESHOLD KEYEX_ORACLE_CHAIN_ID KEYEX_ORACLE_VERSION KEYEX_ORACLE_ANCESTORS KEYEX_ORACLE_PEERS)
ORACLE_REQ=(KEYEX_ORACLE_REGISTRY KEYEX_ORACLE_RH_RPCS KEYEX_ORACLE_SAFE KEYEX_ORACLE_OWNERS KEYEX_ORACLE_THRESHOLD KEYEX_ORACLE_CHAIN_ID KEYEX_ORACLE_VERSION)
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

# build_measure OUT_EIF OUT_JSON — one cold docker build + build-enclave.
# Reads build_one's locals (bash dynamic scope): buildargs, dockerfile, tag.
# nitro-cli is deterministic for a fixed image (measured: 3 runs, identical
# PCR0/1/2), so reproducibility rests entirely on the docker build being
# deterministic — which is what SOURCE_DATE_EPOCH and the pinned bases buy.
build_measure() {
  sudo docker build "${buildargs[@]}" -f "$dockerfile" -t "$tag" .
  sudo nitro-cli build-enclave --docker-uri "$tag" --output-file "$1" > "$2"
  sudo chown "$(id -u):$(id -g)" "$1"
}

S3="s3://$EIF_BUCKET"

# Host bundle suffix: a second network publishes its host plane to host$REL_SUFFIX/
# instead of over the live one. EIFs need none: eif/ is content-addressed.
REL_SUFFIX="${EIF_RELEASE_SUFFIX:-}"
case "$REL_SUFFIX" in
  ""|-[a-z0-9]*) ;;
  *) echo "FATAL: EIF_RELEASE_SUFFIX must start with '-' and be lowercase alnum" >&2; exit 1 ;;
esac

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
  buildargs+=(--build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH")

  echo "=== build $name ($dockerfile) ==="
  echo "    EIF_CONFIG=$EIF_CONFIG"
  for av in "${_args[@]}"; do printf '    %s=%s\n' "$av" "${!av:-<empty>}"; done
  build_measure "$eif" "$WORK/$name.build.json"
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

  # EIF_VERIFY_REPRODUCIBLE=1: rebuild cold and require the same measurement.
  # PCR0 pinned on-chain is only an audit anchor if a third party can re-derive
  # it from this commit; a mismatch here means something unmeasured leaked in.
  if [ -n "${EIF_VERIFY_REPRODUCIBLE:-}" ]; then
    echo "=== $name: reproducibility check — cold rebuild"
    sudo docker rmi -f "$tag" >/dev/null 2>&1 || true
    sudo docker builder prune -af >/dev/null 2>&1 || true
    build_measure "$WORK/$name.rebuild.eif" "$WORK/$name.rebuild.json"
    local r
    for r in PCR0 PCR1 PCR2; do
      local want have
      want=$(jq -r ".Measurements.$r" "$WORK/$name.build.json")
      have=$(jq -r ".Measurements.$r" "$WORK/$name.rebuild.json")
      [ "$want" = "$have" ] || { echo "FATAL: $name $r not reproducible: $want vs $have" >&2; exit 1; }
    done
    if cmp -s "$eif" "$WORK/$name.rebuild.eif"; then
      echo "$name: reproducible — EIF byte-identical"
    else
      echo "$name: reproducible — PCR0/1/2 match; EIF bytes differ only in unmeasured metadata"
    fi
    rm -f "$WORK/$name.rebuild.eif" "$WORK/$name.rebuild.json"
  fi

  # Remember the oracle PCR0 so the pontifex build (built next) pins it as parent.
  [ "$name" = oracle ] && ORACLE_PCR0="$pcr0"

  # The pin is sha384 (this exact file) + PCR0 (the reproducible measurement);
  # EIF bytes may differ across rebuilds in unmeasured metadata, PCR0 may not.
  local sha
  sha=$(sha384sum "$eif" | awk '{print $1}')
  [[ "$sha" =~ ^[0-9a-f]{96}$ ]] || { echo "FATAL: $name bad sha384: $sha" >&2; exit 1; }
  jq '.Measurements' "$WORK/$name.build.json" > "$WORK/$name.pcr0.json"
  jq -n --arg sha "$sha" --arg p0 "$pcr0" --arg p1 "$pcr1" --arg p2 "$pcr2" \
    '{sha384: $sha, PCR0: $p0, PCR1: $p1, PCR2: $p2}' > "$WORK/$name.pcrs.json"
  jq -n --arg sha "$sha" --arg pcr0 "$pcr0" --arg commit "$COMMIT" --arg config "$EIF_CONFIG" \
    '{sha384: $sha, pcr0: $pcr0, commit: $commit, config: $config}' > "$WORK/$name.pin.json"

  retry 3 5 aws s3 cp "$eif"                  "$S3/eif/$sha.eif"
  retry 3 5 aws s3 cp "$WORK/$name.pcr0.json" "$S3/staging/$COMMIT/$name.pcr0.json"
  retry 3 5 aws s3 cp "$WORK/$name.pcrs.json" "$S3/staging/$COMMIT/$name.pcrs.json"
  retry 3 5 aws s3 cp "$WORK/$name.pin.json"  "$S3/staging/$COMMIT/$name.pin.json"
  echo "$name published to $S3/eif/$sha.eif"

  # Reclaim the oracle build cache + image before pontifex builds, so two musl
  # release trees need not co-reside on the 30G builder volume. Cache-independent
  # (digest-pinned bases + --locked): pruning is PCR-neutral.
  sudo docker rmi -f "$tag" >/dev/null 2>&1 || true
  sudo docker builder prune -af >/dev/null 2>&1 || true

  echo "$name PCR0=$pcr0"
}

# publish_host_bundle — copy the host relay plane to S3 for the prod launch
# template. Untrusted and unpinned: a compromised host can only drop or delay
# bytes, since RPC TLS and peer RA-TLS terminate inside the enclave.
publish_host_bundle() {
  local hp="host$REL_SUFFIX"
  echo "=== publish host bundle ($hp) ==="
  retry 3 5 aws s3 cp host/http_connect_proxy.py "$S3/$hp/http_connect_proxy.py"
  retry 3 5 aws s3 cp host/pontifex_host.py      "$S3/$hp/pontifex_host.py"
  retry 3 5 aws s3 cp host/genesis_capture.py    "$S3/$hp/genesis_capture.py"
  retry 3 5 aws s3 cp host/pull_api.py           "$S3/$hp/pull_api.py"
  retry 3 5 aws s3 cp --recursive host/systemd/  "$S3/$hp/systemd/"
  echo "host bundle published to $S3/$hp/"
}

# Run the whole build piped to tee so the full transcript — not just SSM's
# truncated 2500-char tail — lands in S3 on success or failure. The pipeline
# barrier makes tee flush before the upload (no lost-tail race), and
# PIPESTATUS[0] carries the real build rc past the `| tee`.
BUILD_LOG="$(mktemp /tmp/build-eif-XXXXXX.log)"
# Keep the outer shell alive for log upload; fail fast inside the build.
set +e
(
  set -e
  for entry in "${IMAGES[@]}"; do
    build_one "${entry%%:*}" "${entry#*:}"
  done

  publish_host_bundle

  echo "=== keyex EIFs built + published (commit $COMMIT) ==="
  echo "=== pins for infra/live/eif-release.json ==="
  for entry in "${IMAGES[@]}"; do
    jq --arg n "${entry%%:*}" '{($n): .}' "$WORK/${entry%%:*}.pin.json"
  done
) 2>&1 | tee "$BUILD_LOG"
BUILD_RC=${PIPESTATUS[0]}
set -e
aws s3 cp "$BUILD_LOG" "$S3/builds/$COMMIT/build.log" >/dev/null 2>&1 || true
rm -f "$BUILD_LOG"
echo "build log: $S3/builds/$COMMIT/build.log (rc=$BUILD_RC)"
exit "$BUILD_RC"
