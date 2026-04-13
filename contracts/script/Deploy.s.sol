// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/KaskadPriceOracle.sol";
import "../src/KaskadAggregatorV3.sol";
import "../test/mocks/MockVerifiers.sol";

/// @notice Deploy KaskadPriceOracle + per-asset AggregatorV3 wrappers.
///
/// For local/testnet: uses MockAttestationVerifier (accepts any attestation).
/// For production: deploy a NitroAttestationVerifier instead.
///
/// Usage:
///   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --private-key $DEPLOYER_KEY
contract Deploy is Script {
    function run() external {
        // Expected PCR0 (enclave image hash)
        bytes32 expectedPCR0 = vm.envOr("EXPECTED_PCR0", keccak256("kaskad-oracle:v0.1"));

        // Oracle signer address (the enclave's derived address)
        address oracleSigner = vm.envOr(
            "ORACLE_SIGNER",
            address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8) // Anvil account #1
        );

        vm.startBroadcast();

        // Deploy mock verifier (testnet only!)
        MockAttestationVerifier verifier = new MockAttestationVerifier(expectedPCR0, oracleSigner);
        console.log("MockAttestationVerifier:", address(verifier));

        // Deploy oracle (permissionless, no owner)
        KaskadPriceOracle oracle = new KaskadPriceOracle(expectedPCR0, address(verifier));
        console.log("KaskadPriceOracle deployed at:", address(oracle));

        // Register enclave via mock attestation
        oracle.registerEnclave(hex"00");
        console.log("Enclave registered, signer:", oracleSigner);

        // Asset IDs
        bytes32 ethUsd = keccak256("ETH/USD");
        bytes32 btcUsd = keccak256("BTC/USD");
        bytes32 kasUsd = keccak256("KAS/USD");
        bytes32 usdcUsd = keccak256("USDC/USD");
        bytes32 igraUsd = keccak256("IGRA/USD");

        // Deploy aggregator wrappers
        KaskadAggregatorV3 ethAgg = new KaskadAggregatorV3(address(oracle), ethUsd, "ETH / USD");
        KaskadAggregatorV3 btcAgg = new KaskadAggregatorV3(address(oracle), btcUsd, "BTC / USD");
        KaskadAggregatorV3 kasAgg = new KaskadAggregatorV3(address(oracle), kasUsd, "KAS / USD");
        KaskadAggregatorV3 usdcAgg = new KaskadAggregatorV3(address(oracle), usdcUsd, "USDC / USD");
        KaskadAggregatorV3 igraAgg = new KaskadAggregatorV3(address(oracle), igraUsd, "IGRA / USD");

        console.log("ETH/USD Aggregator:", address(ethAgg));
        console.log("BTC/USD Aggregator:", address(btcAgg));
        console.log("KAS/USD Aggregator:", address(kasAgg));
        console.log("USDC/USD Aggregator:", address(usdcAgg));
        console.log("IGRA/USD Aggregator:", address(igraAgg));

        vm.stopBroadcast();
    }
}
