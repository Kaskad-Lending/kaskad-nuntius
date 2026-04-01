// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/KaskadPriceOracle.sol";
import "../src/KaskadAggregatorV3.sol";
import "../src/KaskadRouter.sol";
import "../test/mocks/MockVerifiers.sol";

/// @notice Deploy TEE Oracle stack to Galleon testnet.
///
/// Deploys: KaskadPriceOracle + 4 AggregatorV3 wrappers + KaskadRouter.
/// IGRA and KSKD stay on MockPriceOracle (governance/computed prices).
///
/// After deploy, run in lending-onchain:
///   AaveOracle.setAssetSources([WETH, WBTC, USDC, WIKAS], [ethAgg, btcAgg, usdcAgg, kasAgg])
///
/// Usage:
///   forge script script/DeployGalleon.s.sol \
///     --rpc-url https://galleon-testnet.igralabs.com:8545 \
///     --broadcast --private-key $DEPLOYER_KEY
contract DeployGalleon is Script {
    // ─── Galleon testnet addresses (from lending-onchain interface setup.json) ──
    address constant AAVE_POOL    = 0xA1D84fc43f7F2D803a2d64dbBa4A90A9A79E3F24;
    address constant AAVE_ORACLE  = 0xc1198A9d400306a0406fD3E3Ad67140b3D059f48;

    function run() external {
        bytes32 expectedPCR0 = vm.envOr("EXPECTED_PCR0", keccak256("kaskad-oracle:v0.1"));
        address oracleSigner = vm.envAddress("ORACLE_SIGNER");
        address aavePool = vm.envOr("AAVE_POOL", address(AAVE_POOL));

        vm.startBroadcast();

        // ─── 1. Oracle + MockVerifier (testnet) ──────────────────
        MockAttestationVerifier verifier = new MockAttestationVerifier(expectedPCR0, oracleSigner);
        console.log("MockAttestationVerifier:", address(verifier));

        KaskadPriceOracle oracle = new KaskadPriceOracle(expectedPCR0, address(verifier));
        console.log("KaskadPriceOracle:", address(oracle));

        oracle.registerEnclave(hex"00");
        console.log("Enclave registered, signer:", oracleSigner);

        // ─── 2. AggregatorV3 wrappers (4 assets — IGRA/KSKD stay on MockOracle) ──
        bytes32 ethUsd  = keccak256("ETH/USD");
        bytes32 btcUsd  = keccak256("BTC/USD");
        bytes32 usdcUsd = keccak256("USDC/USD");
        bytes32 kasUsd  = keccak256("KAS/USD");

        KaskadAggregatorV3 ethAgg  = new KaskadAggregatorV3(address(oracle), ethUsd,  "ETH / USD");
        KaskadAggregatorV3 btcAgg  = new KaskadAggregatorV3(address(oracle), btcUsd,  "BTC / USD");
        KaskadAggregatorV3 usdcAgg = new KaskadAggregatorV3(address(oracle), usdcUsd, "USDC / USD");
        KaskadAggregatorV3 kasAgg  = new KaskadAggregatorV3(address(oracle), kasUsd,  "KAS / USD");

        console.log("ETH/USD  Aggregator:", address(ethAgg));
        console.log("BTC/USD  Aggregator:", address(btcAgg));
        console.log("USDC/USD Aggregator:", address(usdcAgg));
        console.log("KAS/USD  Aggregator:", address(kasAgg));

        // ─── 3. Router ───────────────────────────────────────────
        if (aavePool != address(0)) {
            KaskadRouter router = new KaskadRouter(address(oracle), aavePool);
            console.log("KaskadRouter:", address(router));
        } else {
            console.log("KaskadRouter: SKIPPED (set AAVE_POOL env to deploy)");
        }

        vm.stopBroadcast();

        // ─── Integration instructions ─────────────────────────────
        console.log("");
        console.log("=== Next step: swap oracle sources in lending-onchain ===");
        console.log("AaveOracle.setAssetSources(");
        console.log("  [WETH, WBTC, USDC, WIKAS],");
        console.log("  [ethAgg, btcAgg, usdcAgg, kasAgg]");
        console.log(")");
        console.log("AaveOracle:", AAVE_ORACLE);
    }
}
