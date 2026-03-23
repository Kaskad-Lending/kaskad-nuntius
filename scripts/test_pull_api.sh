#!/usr/bin/env bash
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CONTRACTS_DIR="${PROJECT_DIR}/contracts"
ANVIL_PORT=8547
RPC_URL="http://127.0.0.1:${ANVIL_PORT}"
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ALB_URL="http://kaskad-oracle-alb-670133639.us-east-1.elb.amazonaws.com"

echo "▸ Fetching prices from ALB..."
RESPONSE=$(curl -s $ALB_URL/prices)
SIGNER_ADDR=$(echo "$RESPONSE" | jq -r '.signer')

if [ -z "$SIGNER_ADDR" ] || [ "$SIGNER_ADDR" == "null" ]; then
    echo "✗ Failed to get signer from ALB response."
    exit 1
fi
echo "  ✓ Signer: $SIGNER_ADDR"

echo "▸ Starting Anvil..."
anvil --port ${ANVIL_PORT} --silent &
ANVIL_PID=$!
trap "kill $ANVIL_PID 2>/dev/null || true" EXIT
sleep 2

echo "▸ Deploying contracts..."
cd ${CONTRACTS_DIR}
DEPLOY_OUTPUT=$(ORACLE_SIGNER=${SIGNER_ADDR} forge script script/Deploy.s.sol --rpc-url ${RPC_URL} --broadcast --private-key ${DEPLOYER_KEY} 2>/dev/null)
ORACLE_ADDR=$(echo "$DEPLOY_OUTPUT" | grep "KaskadPriceOracle deployed at:" | awk '{print $NF}')

if [ -z "$ORACLE_ADDR" ]; then
    echo "  ✗ Failed to find deployed Oracle address"
    exit 1
fi
echo "  ✓ Oracle at: ${ORACLE_ADDR}"

echo "▸ Pushing prices to Anvil..."
ASSETS_LEN=$(echo "$RESPONSE" | jq '.prices | length')

for i in $(seq 0 $((ASSETS_LEN-1))); do
    ASSET_ID=$(echo "$RESPONSE" | jq -r ".prices[$i].asset_id")
    ASSET_SYMBOL=$(echo "$RESPONSE" | jq -r ".prices[$i].asset_symbol")
    PRICE=$(echo "$RESPONSE" | jq -r ".prices[$i].price")
    TIMESTAMP=$(echo "$RESPONSE" | jq -r ".prices[$i].timestamp")
    NUM_SOURCES=$(echo "$RESPONSE" | jq -r ".prices[$i].num_sources")
    SOURCES_HASH=$(echo "$RESPONSE" | jq -r ".prices[$i].sources_hash")
    SIGNATURE=$(echo "$RESPONSE" | jq -r ".prices[$i].signature")

    echo "  → Pushing $ASSET_SYMBOL ($PRICE)..."
    
    # Run cast send
    cast send ${ORACLE_ADDR} "updatePrice(bytes32,uint256,uint256,uint8,bytes32,bytes)" \
      ${ASSET_ID} ${PRICE} ${TIMESTAMP} ${NUM_SOURCES} ${SOURCES_HASH} ${SIGNATURE} \
      --rpc-url ${RPC_URL} --private-key ${DEPLOYER_KEY} > /dev/null

    echo "  ✓ Pushed."
done

echo "▸ Verifying on-chain data..."
for i in $(seq 0 $((ASSETS_LEN-1))); do
    ASSET_ID=$(echo "$RESPONSE" | jq -r ".prices[$i].asset_id")
    ASSET_SYMBOL=$(echo "$RESPONSE" | jq -r ".prices[$i].asset_symbol")
    
    RESULT=$(cast call ${ORACLE_ADDR} "getLatestPrice(bytes32)(uint256,uint256,uint8,uint80)" ${ASSET_ID} --rpc-url ${RPC_URL} 2>/dev/null)
    ONCHAIN_PRICE=$(echo "$RESULT" | head -1 | awk '{print $1}')
    
    echo "  ✓ $ASSET_SYMBOL on-chain price: $ONCHAIN_PRICE"
done

echo "✅ Success!"
