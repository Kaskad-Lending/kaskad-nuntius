#!/bin/sh
# Runs the volume-monitor in a terminal, with the host kept awake by
# caffeinate for the duration of the run.
#
#   ./run.sh          # 1 hour (default)
#   ./run.sh 30m      # 30 minutes
#   ./run.sh 24h      # 24 hours
#   ./run.sh 900      # raw seconds
#
# Prints a per-crypto comparison table every 5 minutes, then the final
# report (with venue-reported 24h volumes for comparison). Ctrl-C stops
# the run early and still produces the final report. Output persists in
# volmon-out/run-<date>/ (state.json written every 30s, readable at any
# time via: volume-monitor --report <dir>/state.json).
set -e
cd "$(dirname "$0")"
DUR="${1:-1h}"
case "$DUR" in
  *h) N="${DUR%h}"; UNIT=3600 ;;
  *m) N="${DUR%m}"; UNIT=60 ;;
  *)  N="$DUR";     UNIT=1 ;;
esac
# Digits only, no leading zero: rejects forms like 90s/1H/1.5h up front
# and keeps $(( )) from parsing 08/09 as octal.
case "$N" in
  ''|*[!0-9]*|0[0-9]*)
    echo "invalid duration '$DUR' (use e.g. 45m, 2h, or raw seconds)" >&2
    exit 1 ;;
esac
SECS=$(( N * UNIT ))
OUT="volmon-out/run-$(date +%Y%m%d-%H%M%S)"
export PATH="$HOME/.cargo/bin:$PATH"
cargo build --release --quiet
mkdir -p "$OUT"
echo "monitoring ${SECS}s on venues from config/exchanges.json"
echo "  output: $OUT/  (connection log: $OUT/run.log)"
echo "  first live table in 5 min; Ctrl-C ends early (final report still written)"
exec caffeinate -is ./target/release/volume-monitor \
  --config ../../config/exchanges.json \
  --out "$OUT" \
  --duration-secs "$SECS" \
  2>"$OUT/run.log"
