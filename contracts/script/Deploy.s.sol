// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/KaskadPriceOracle.sol";
import "../src/KaskadAggregatorV3.sol";

/// @notice Deploy KaskadPriceOracle + per-asset AggregatorV3 wrappers.
/// Usage:
///   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --private-key $DEPLOYER_KEY
contract Deploy is Script {
    function run() external {
        // Oracle signer address (from ORACLE_SIGNER env or default Anvil key #1)
        address oracleSigner = vm.envOr(
            "ORACLE_SIGNER",
            address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8) // Anvil account #1
        );

        vm.startBroadcast();

        // Deploy oracle
        KaskadPriceOracle oracle = new KaskadPriceOracle(oracleSigner);
        console.log("KaskadPriceOracle deployed at:", address(oracle));

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
