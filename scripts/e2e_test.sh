#!/usr/bin/env bash
# E2E test: Anvil → Deploy contracts → Oracle signs → Push to contract → Verify on-chain
set -euo pipefail

echo "═══════════════════════════════════════════════════"
echo "  Kaskad Oracle E2E Test"
echo "═══════════════════════════════════════════════════"

# ─── Config ───────────────────────────────────────────
ANVIL_PORT=8546
RPC_URL="http://127.0.0.1:${ANVIL_PORT}"

# Anvil default accounts
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # account #0
ORACLE_SIGNER_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"  # account #1
ORACLE_SIGNER_ADDR="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

TX_SENDER_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"  # account #2

CONTRACTS_DIR="$(dirname "$0")/../contracts"
PROJECT_DIR="$(dirname "$0")/.."

# ─── 1. Start Anvil ──────────────────────────────────
echo ""
echo "▸ Starting Anvil on port ${ANVIL_PORT}..."
anvil --port ${ANVIL_PORT} --silent &
ANVIL_PID=$!
trap "kill $ANVIL_PID 2>/dev/null || true" EXIT
sleep 1

# Verify Anvil is running
if ! curl -s ${RPC_URL} -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' > /dev/null 2>&1; then
  echo "✗ Anvil failed to start"
  exit 1
fi
echo "  ✓ Anvil running (PID: ${ANVIL_PID})"

# ─── 2. Deploy contracts ─────────────────────────────
echo ""
echo "▸ Deploying contracts..."
DEPLOYER_ADDR=$(cast wallet address ${DEPLOYER_KEY})
DEPLOY_OUTPUT=$(cd ${CONTRACTS_DIR} && \
  ORACLE_SIGNER=${ORACLE_SIGNER_ADDR} \
  ORACLE_ADMIN=${DEPLOYER_ADDR} \
  forge script script/DeployLocal.s.sol \
    --rpc-url ${RPC_URL} \
    --broadcast \
    --private-key ${DEPLOYER_KEY} \
    2>&1)

echo "$DEPLOY_OUTPUT" | grep "deployed at\|Aggregator"

# Extract oracle contract address
ORACLE_ADDR=$(echo "$DEPLOY_OUTPUT" | grep "KaskadPriceOracle deployed" | awk '{print $NF}')
ETH_AGG_ADDR=$(echo "$DEPLOY_OUTPUT" | grep "ETH/USD Aggregator" | awk '{print $NF}')

if [ -z "$ORACLE_ADDR" ]; then
  echo "✗ Failed to extract oracle address from deploy output"
  exit 1
fi
echo "  ✓ Oracle deployed at: ${ORACLE_ADDR}"

# ─── 3. Verify oracle signer is set ──────────────────
echo ""
echo "▸ Verifying oracle signer..."
IS_VALID=$(cast call ${ORACLE_ADDR} "validSigner(address)(bool)" ${ORACLE_SIGNER_ADDR} --rpc-url ${RPC_URL})
echo "  validSigner(${ORACLE_SIGNER_ADDR}) = ${IS_VALID}"
if [ "${IS_VALID}" != "true" ]; then
  echo "✗ Expected signer not in valid-signer set!"
  exit 1
fi
echo "  ✓ Signer in valid set"

# ─── 4. Sign and submit a price update ───────────────
echo ""
echo "▸ Signing ETH/USD price update..."

# Compute assetId = keccak256("ETH/USD")
ASSET_ID=$(cast keccak "ETH/USD")

# Price: $2129.26 with 8 decimals = 212926000000
PRICE="212926000000"
TIMESTAMP=$(date +%s)
NUM_SOURCES="4"
SOURCES_HASH=$(cast keccak "binance|okx|bybit|coinbase")

echo "  Asset ID:     ${ASSET_ID}"
echo "  Price:        ${PRICE} (= \$2129.26)"
echo "  Timestamp:    ${TIMESTAMP}"
echo "  Sources:      ${NUM_SOURCES}"
echo "  Sources Hash: ${SOURCES_HASH}"

# Compute message hash = keccak256(abi.encodePacked(assetId, price, timestamp, numSources, sourcesHash))
PACKED=$(cast abi-encode "f(bytes32,uint256,uint256,uint8,bytes32)" \
  ${ASSET_ID} ${PRICE} ${TIMESTAMP} ${NUM_SOURCES} ${SOURCES_HASH} | cut -c3-)

# abi.encodePacked is just concatenation of the raw types
# For encodePacked: bytes32 (32) + uint256 (32) + uint64 (8) + uint8 (1) + bytes32 (32) = 105 bytes
# But we use abi.encodePacked in Solidity which for uint256 timestamp uses 32 bytes
# Let's use cast to generate the exact same hash
MSG_HASH=$(cast keccak $(cast abi-encode --packed "f(bytes32,uint256,uint256,uint8,bytes32)" \
  ${ASSET_ID} ${PRICE} ${TIMESTAMP} ${NUM_SOURCES} ${SOURCES_HASH}))

echo "  Message Hash: ${MSG_HASH}"

# EIP-191 personal sign: keccak256("\x19Ethereum Signed Message:\n32" + msgHash)
SIGNATURE=$(cast wallet sign --private-key ${ORACLE_SIGNER_KEY} ${MSG_HASH})

echo "  Signature:    ${SIGNATURE:0:20}..."

# ─── 5. Submit to contract ────────────────────────────
echo ""
echo "▸ Submitting price update to contract..."
cast send ${ORACLE_ADDR} \
  "updatePrice(bytes32,uint256,uint256,uint8,bytes32,bytes)" \
  ${ASSET_ID} ${PRICE} ${TIMESTAMP} ${NUM_SOURCES} ${SOURCES_HASH} ${SIGNATURE} \
  --rpc-url ${RPC_URL} \
  --private-key ${TX_SENDER_KEY} > /dev/null 2>&1

echo "  ✓ TX submitted"

# ─── 6. Verify on-chain ──────────────────────────────
echo ""
echo "▸ Reading price from contract..."
RESULT=$(cast call ${ORACLE_ADDR} "getLatestPrice(bytes32)(uint256,uint256,uint8,uint80)" \
  ${ASSET_ID} --rpc-url ${RPC_URL})

# Parse: cast returns formatted numbers like "212926000000 [2.129e11]", extract first word
STORED_PRICE=$(echo "$RESULT" | head -1 | awk '{print $1}')
STORED_TS=$(echo "$RESULT" | sed -n '2p' | awk '{print $1}')
STORED_SOURCES=$(echo "$RESULT" | sed -n '3p' | awk '{print $1}')
STORED_ROUND=$(echo "$RESULT" | sed -n '4p' | awk '{print $1}')

echo "  Stored price:     ${STORED_PRICE}"
echo "  Stored timestamp: ${STORED_TS}"
echo "  Stored sources:   ${STORED_SOURCES}"
echo "  Round ID:         ${STORED_ROUND}"

# Verify
if [ "${STORED_PRICE}" = "${PRICE}" ]; then
  echo "  ✓ Price matches!"
else
  echo ""
  echo "  ✗ Price mismatch: expected ${PRICE}, got ${STORED_PRICE}"
  exit 1
fi

# ─── 7. Test AggregatorV3 wrapper ─────────────────────
echo ""
echo "▸ Testing AggregatorV3 wrapper..."
if [ -n "${ETH_AGG_ADDR}" ]; then
  LATEST_ANSWER=$(cast call ${ETH_AGG_ADDR} "latestAnswer()(int256)" --rpc-url ${RPC_URL} | awk '{print $1}')
  DECIMALS=$(cast call ${ETH_AGG_ADDR} "decimals()(uint8)" --rpc-url ${RPC_URL} | awk '{print $1}')
  DESC=$(cast call ${ETH_AGG_ADDR} "description()(string)" --rpc-url ${RPC_URL})

  echo "  latestAnswer(): ${LATEST_ANSWER}"
  echo "  decimals():     ${DECIMALS}"
  echo "  description():  ${DESC}"

  if [ "${LATEST_ANSWER}" = "${PRICE}" ]; then
    echo "  ✓ AggregatorV3 wrapper works!"
  else
    echo "  ✗ AggregatorV3 answer mismatch"
    exit 1
  fi
fi

# ─── 8. Test rejection of invalid signature ───────────
echo ""
echo "▸ Testing invalid signature rejection..."
BAD_SIG="0x$(python3 -c "print('00' * 65)")"
RESULT=$(cast send ${ORACLE_ADDR} \
  "updatePrice(bytes32,uint256,uint256,uint8,bytes32,bytes)" \
  ${ASSET_ID} ${PRICE} $((TIMESTAMP + 1)) ${NUM_SOURCES} ${SOURCES_HASH} ${BAD_SIG} \
  --rpc-url ${RPC_URL} \
  --private-key ${TX_SENDER_KEY} \
  2>&1 || true)

if echo "$RESULT" | grep -qi "revert\|error\|InvalidSignature"; then
  echo "  ✓ Invalid signature correctly rejected"
else
  echo "  ✗ Invalid signature was NOT rejected — this is a bug!"
  exit 1
fi

# ─── 9. Test stale timestamp rejection ────────────────
echo ""
echo "▸ Testing stale timestamp rejection..."
OLD_TIMESTAMP=$((TIMESTAMP - 1))
OLD_MSG_HASH=$(cast keccak $(cast abi-encode --packed "f(bytes32,uint256,uint256,uint8,bytes32)" \
  ${ASSET_ID} ${PRICE} ${OLD_TIMESTAMP} ${NUM_SOURCES} ${SOURCES_HASH}))
OLD_SIG=$(cast wallet sign --private-key ${ORACLE_SIGNER_KEY} ${OLD_MSG_HASH})

RESULT=$(cast send ${ORACLE_ADDR} \
  "updatePrice(bytes32,uint256,uint256,uint8,bytes32,bytes)" \
  ${ASSET_ID} ${PRICE} ${OLD_TIMESTAMP} ${NUM_SOURCES} ${SOURCES_HASH} ${OLD_SIG} \
  --rpc-url ${RPC_URL} \
  --private-key ${TX_SENDER_KEY} \
  2>&1 || true)

if echo "$RESULT" | grep -qi "revert\|error\|StalePrice"; then
  echo "  ✓ Stale timestamp correctly rejected"
else
  echo "  ✗ Stale timestamp was NOT rejected — this is a bug!"
  exit 1
fi

# ─── Done ─────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════"
echo "  ✅ All E2E tests passed!"
echo "═══════════════════════════════════════════════════"
