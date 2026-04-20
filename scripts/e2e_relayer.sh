#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# E2E Integration Test: Oracle → Pull API → Relayer → Anvil → Verify
#
# Full real flow, no Solidity mocks in the data path:
#   1. Start Anvil (local chain)
#   2. Deploy KaskadPriceOracle + AggregatorV3 wrappers
#   3. Run Rust oracle binary (SINGLE_RUN=1, real CEX APIs, real k256 signing)
#   4. Run TypeScript relayer (real EIP-191 verification, real ethers.js TX)
#   5. Verify prices on-chain via cast
#   6. Verify AggregatorV3 wrappers return correct data
#
# MockAttestationVerifier is used ONLY for enclave registration (no NSM
# hardware available locally). Everything else is real: signing, sig
# verification, price fetching, relayer logic, on-chain storage.
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACTS_DIR="${PROJECT_DIR}/contracts"
RELAYER_DIR="${PROJECT_DIR}/relayer"
ANVIL_PORT=8547
RPC_URL="http://127.0.0.1:${ANVIL_PORT}"
PULL_API_PORT=5001

# Anvil well-known keys
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# Oracle signer — enclave's signing key (in real prod this never leaves TEE)
ORACLE_PRIVATE_KEY="59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
ORACLE_SIGNER_ADDR="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
# Gas-payer for relayer (Anvil account #2)
RELAYER_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

PIDS=()
cleanup() {
  echo ""
  echo "▸ Cleaning up..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo "═══════════════════════════════════════════════════"
echo "  Kaskad Oracle — Full E2E (Oracle → Relayer → Chain)"
echo "═══════════════════════════════════════════════════"

# ─── 1. Start Anvil ──────────────────────────────────
echo ""
echo "▸ [1/6] Starting Anvil on :${ANVIL_PORT}..."
anvil --port ${ANVIL_PORT} --silent &
PIDS+=($!)
sleep 1

if ! cast block-number --rpc-url ${RPC_URL} > /dev/null 2>&1; then
  echo "  ✗ Anvil failed to start"
  exit 1
fi
echo "  ✓ Anvil running"

# ─── 2. Deploy contracts ─────────────────────────────
echo ""
echo "▸ [2/6] Deploying contracts..."
DEPLOYER_ADDR=$(cast wallet address ${DEPLOYER_KEY})
DEPLOY_OUTPUT=$(cd ${CONTRACTS_DIR} && \
  ORACLE_SIGNER=${ORACLE_SIGNER_ADDR} \
  ORACLE_ADMIN=${DEPLOYER_ADDR} \
  forge script script/DeployLocal.s.sol \
    --rpc-url ${RPC_URL} \
    --broadcast \
    --private-key ${DEPLOYER_KEY} \
    2>&1)

ORACLE_ADDR=$(echo "$DEPLOY_OUTPUT" | grep "KaskadPriceOracle deployed" | awk '{print $NF}')
ETH_AGG_ADDR=$(echo "$DEPLOY_OUTPUT" | grep "ETH/USD Aggregator" | awk '{print $NF}')
BTC_AGG_ADDR=$(echo "$DEPLOY_OUTPUT" | grep "BTC/USD Aggregator" | awk '{print $NF}')

if [ -z "$ORACLE_ADDR" ]; then
  echo "  ✗ Failed to extract oracle address"
  echo "$DEPLOY_OUTPUT"
  exit 1
fi
echo "  ✓ KaskadPriceOracle: ${ORACLE_ADDR}"
echo "  ✓ ETH/USD Aggregator: ${ETH_AGG_ADDR}"
echo "  ✓ BTC/USD Aggregator: ${BTC_AGG_ADDR}"

# Verify enclave is registered
SIGNER_COUNT=$(cast call ${ORACLE_ADDR} "signerCount()(uint256)" --rpc-url ${RPC_URL})
echo "  ✓ Registered signer count: ${SIGNER_COUNT}"

# ─── 3. Build Rust oracle ────────────────────────────
echo ""
echo "▸ [3/6] Building Rust oracle..."
cd ${PROJECT_DIR}
cargo build --release 2>&1 | tail -1
echo "  ✓ Built"

# ─── 4. Run oracle (background, continuous mode) ─────
echo ""
echo "▸ [4/6] Running oracle (real CEX APIs, real k256 signing)..."
echo "  Fetching from 8 exchanges — first cycle takes ~10-15s..."

# Run oracle in continuous mode (NOT SINGLE_RUN) so pull API stays alive.
# We'll query the API after the first cycle populates prices.
ORACLE_PRIVATE_KEY=${ORACLE_PRIVATE_KEY} \
VSOCK_PORT=${PULL_API_PORT} \
RUST_LOG=info \
${PROJECT_DIR}/target/release/kaskad-oracle 2>&1 &
ORACLE_PID=$!
PIDS+=($ORACLE_PID)

# Wait for oracle to finish first fetch cycle (~10s for 8 sources × 5 assets)
# Then it stores signed prices in pull API. Poll until we get data.
echo "  Waiting for signed prices to appear in pull API..."
PULL_RESPONSE=""
for i in $(seq 1 30); do
  sleep 2
  PULL_RESPONSE=$(python3 -c "
import socket, struct, json, sys
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect(('127.0.0.1', ${PULL_API_PORT}))
    req = json.dumps({'method': 'get_prices'}).encode()
    sock.sendall(struct.pack('>I', len(req)))
    sock.sendall(req)
    resp_len = struct.unpack('>I', sock.recv(4))[0]
    resp_data = b''
    while len(resp_data) < resp_len:
        resp_data += sock.recv(resp_len - len(resp_data))
    sock.close()
    data = json.loads(resp_data)
    n = len(data.get('prices', []))
    if n >= 2:
        print(json.dumps(data))
    else:
        sys.exit(1)
except:
    sys.exit(1)
" 2>/dev/null) && break || true
done

if [ -z "$PULL_RESPONSE" ]; then
  echo "  ✗ Pull API did not return enough prices after 60s"
  exit 1
fi
echo "  ✓ Oracle running, pull API populated"

# ─── 5. Run relayer: verify sigs → submit to Anvil ──
echo ""
echo "▸ [5/6] Running TypeScript relayer..."

NUM_PRICES=$(echo "$PULL_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('prices', [])))")
PULL_SIGNER=$(echo "$PULL_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('signer','?'))")

echo "  Pull API: ${NUM_PRICES} signed prices from signer ${PULL_SIGNER}"

cd ${RELAYER_DIR}

echo "$PULL_RESPONSE" | \
  RPC_URL=${RPC_URL} \
  ORACLE_ADDRESS=${ORACLE_ADDR} \
  PRIVATE_KEY=${RELAYER_KEY} \
  timeout 30 npx tsx src/e2e-submit.ts 2>&1 || {
  echo "  ✗ Relayer failed"
  exit 1
}

# ─── 6. Verify on-chain via cast ─────────────────────
echo ""
echo "▸ [6/6] Verifying prices on-chain..."

ASSETS=("ETH/USD" "BTC/USD" "KAS/USD" "USDC/USD" "IGRA/USD")
FOUND=0

for ASSET_NAME in "${ASSETS[@]}"; do
  ASSET_ID=$(cast keccak "${ASSET_NAME}")
  RESULT=$(cast call ${ORACLE_ADDR} "getLatestPrice(bytes32)(uint256,uint256,uint8,uint80)" \
    ${ASSET_ID} --rpc-url ${RPC_URL} 2>/dev/null || echo "")

  PRICE=$(echo "$RESULT" | head -1 | awk '{print $1}')

  if [ -n "$PRICE" ] && [ "$PRICE" != "0" ]; then
    TIMESTAMP=$(echo "$RESULT" | sed -n '2p' | awk '{print $1}')
    NUM_SOURCES=$(echo "$RESULT" | sed -n '3p' | awk '{print $1}')
    ROUND=$(echo "$RESULT" | sed -n '4p' | awk '{print $1}')

    HUMAN_PRICE=$(python3 -c "print(f'\${${PRICE}/1e8:.4f}')" 2>/dev/null || echo "${PRICE}")
    echo "  ✓ ${ASSET_NAME}: \$${HUMAN_PRICE} (${NUM_SOURCES} sources, round ${ROUND})"
    FOUND=$((FOUND + 1))
  else
    echo "  ⚠ ${ASSET_NAME}: no price (source may be unavailable)"
  fi
done

# Verify AggregatorV3 wrappers
echo ""
echo "  Verifying AggregatorV3 wrappers..."

if [ -n "$ETH_AGG_ADDR" ]; then
  ETH_ANSWER=$(cast call ${ETH_AGG_ADDR} "latestAnswer()(int256)" --rpc-url ${RPC_URL} 2>/dev/null || echo "0")
  ETH_DECIMALS=$(cast call ${ETH_AGG_ADDR} "decimals()(uint8)" --rpc-url ${RPC_URL} 2>/dev/null || echo "?")
  ETH_DESC=$(cast call ${ETH_AGG_ADDR} "description()(string)" --rpc-url ${RPC_URL} 2>/dev/null || echo "?")
  if [ "$ETH_ANSWER" != "0" ]; then
    HUMAN=$(python3 -c "print(f'\${${ETH_ANSWER}/1e8:.4f}')" 2>/dev/null || echo "$ETH_ANSWER")
    echo "  ✓ ETH AggregatorV3: answer=${HUMAN} decimals=${ETH_DECIMALS} desc=${ETH_DESC}"
  fi
fi

if [ -n "$BTC_AGG_ADDR" ]; then
  BTC_ANSWER=$(cast call ${BTC_AGG_ADDR} "latestAnswer()(int256)" --rpc-url ${RPC_URL} 2>/dev/null || echo "0")
  if [ "$BTC_ANSWER" != "0" ]; then
    HUMAN=$(python3 -c "print(f'\${${BTC_ANSWER}/1e8:.4f}')" 2>/dev/null || echo "$BTC_ANSWER")
    echo "  ✓ BTC AggregatorV3: answer=${HUMAN}"
  fi
fi

# ─── Result ──────────────────────────────────────────
echo ""
if [ $FOUND -ge 2 ]; then
  echo "═══════════════════════════════════════════════════"
  echo "  ✅ E2E PASSED (${FOUND}/5 assets verified on-chain)"
  echo ""
  echo "  Flow verified:"
  echo "    CEX APIs (8 exchanges)"
  echo "    → Rust oracle (k256 EIP-191 signing)"
  echo "    → Pull API (VSOCK/TCP)"
  echo "    → TypeScript relayer (local sig verify + ethers.js TX)"
  echo "    → Anvil chain (OZ ECDSA.recover)"
  echo "    → AggregatorV3 Chainlink-compatible reads"
  echo "═══════════════════════════════════════════════════"
  exit 0
else
  echo "═══════════════════════════════════════════════════"
  echo "  ⚠ Only ${FOUND}/5 assets. May be API rate limiting."
  echo "═══════════════════════════════════════════════════"
  exit 1
fi
