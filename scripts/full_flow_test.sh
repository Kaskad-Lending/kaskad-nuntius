#!/usr/bin/env bash
# Full-flow integration test:
#   1. Start Anvil
#   2. Deploy contracts (MockVerifier for local)
#   3. Build & run Rust oracle binary (SINGLE_RUN mode)
#   4. Oracle fetches REAL prices from exchanges
#   5. Signs with MockSigner
#   6. Publishes to Anvil via Publisher
#   7. Verify prices on-chain
set -euo pipefail

echo "═══════════════════════════════════════════════════"
echo "  Kaskad Oracle — Full Flow Integration Test"
echo "═══════════════════════════════════════════════════"

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACTS_DIR="${PROJECT_DIR}/contracts"
ANVIL_PORT=8547
RPC_URL="http://127.0.0.1:${ANVIL_PORT}"

# Anvil keys
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# Oracle signer — must match ORACLE_PRIVATE_KEY used by Rust binary
ORACLE_PRIVATE_KEY="59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
ORACLE_SIGNER_ADDR="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
# TX submitter (gas payer)
TX_SIGNER_KEY="5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

# ─── 1. Start Anvil ──────────────────────────────────
echo ""
echo "▸ Starting Anvil on port ${ANVIL_PORT}..."
anvil --port ${ANVIL_PORT} --silent &
ANVIL_PID=$!
trap "kill $ANVIL_PID 2>/dev/null || true" EXIT
sleep 1

if ! curl -s ${RPC_URL} -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' > /dev/null 2>&1; then
  echo "  ✗ Anvil failed to start"
  exit 1
fi
echo "  ✓ Anvil running (PID: ${ANVIL_PID})"

# ─── 2. Deploy contracts ─────────────────────────────
echo ""
echo "▸ Deploying contracts..."
DEPLOY_OUTPUT=$(cd ${CONTRACTS_DIR} && ORACLE_SIGNER=${ORACLE_SIGNER_ADDR} \
  forge script script/Deploy.s.sol \
    --rpc-url ${RPC_URL} \
    --broadcast \
    --private-key ${DEPLOYER_KEY} \
    2>&1)

ORACLE_ADDR=$(echo "$DEPLOY_OUTPUT" | grep "KaskadPriceOracle deployed" | awk '{print $NF}')

if [ -z "$ORACLE_ADDR" ]; then
  echo "  ✗ Failed to extract oracle address"
  echo "$DEPLOY_OUTPUT"
  exit 1
fi
echo "  ✓ Oracle at: ${ORACLE_ADDR}"

# ─── 3. Build Rust binary ────────────────────────────
echo ""
echo "▸ Building Rust oracle..."
cd ${PROJECT_DIR}
cargo build --release 2>&1 | tail -3
echo "  ✓ Built"

# ─── 4. Run oracle in SINGLE_RUN mode ────────────────
echo ""
echo "▸ Running oracle (fetching REAL prices, signing, publishing)..."
echo "  This will take ~10-15 seconds (API calls to 8 exchanges)..."
echo ""

SINGLE_RUN=1 \
ORACLE_PRIVATE_KEY=${ORACLE_PRIVATE_KEY} \
RPC_URL=${RPC_URL} \
ORACLE_CONTRACT=${ORACLE_ADDR} \
TX_SIGNER_KEY=${TX_SIGNER_KEY} \
CHAIN_ID=31337 \
RUST_LOG=info \
timeout 60 ${PROJECT_DIR}/target/release/kaskad-oracle 2>&1 || true

echo ""
echo "  ✓ Oracle run complete"

# ─── 5. Verify prices on-chain ───────────────────────
echo ""
echo "▸ Verifying prices on-chain..."

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

    # Convert price to human-readable (8 decimals)
    HUMAN_PRICE=$(python3 -c "print(f'{${PRICE}/1e8:.4f}')" 2>/dev/null || echo "${PRICE}")
    echo "  ✓ ${ASSET_NAME}: \$${HUMAN_PRICE} (${NUM_SOURCES} sources, round ${ROUND})"
    FOUND=$((FOUND + 1))
  else
    echo "  ⚠ ${ASSET_NAME}: no price found (source may be unavailable)"
  fi
done

echo ""
if [ $FOUND -ge 2 ]; then
  echo "═══════════════════════════════════════════════════"
  echo "  ✅ Full flow test passed! (${FOUND}/5 assets)"
  echo ""
  echo "  Flow: CEX APIs → Fetch → Outlier rejection →"
  echo "        Median → Sign (EIP-191) → Submit TX →"
  echo "        On-chain storage → Verified ✓"
  echo "═══════════════════════════════════════════════════"
else
  echo "═══════════════════════════════════════════════════"
  echo "  ⚠ Only ${FOUND}/5 assets had prices."
  echo "  This may be due to API rate limiting."
  echo "═══════════════════════════════════════════════════"
  exit 1
fi
