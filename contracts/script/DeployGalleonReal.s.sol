// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/KaskadPriceOracle.sol";
import "../src/KaskadAggregatorV3.sol";
import "../src/KaskadRouter.sol";
import "../src/NitroAttestationVerifier.sol";
import "nitro-prover/CertManager.sol";
import {NitroProver} from "nitro-prover/NitroProver.sol";

/// @notice Deploy full TEE Oracle stack to Galleon with REAL Nitro attestation.
///         No mocks. CertManager → NitroProver → NitroAttestationVerifier → Oracle → Aggregators → Router.
contract DeployGalleonReal is Script {
    address constant AAVE_POOL = 0xA1D84fc43f7F2D803a2d64dbBa4A90A9A79E3F24;

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        bytes memory attestationDoc = vm.envBytes("ATTESTATION_DOC");

        vm.startBroadcast(deployerKey);

        // ─── 1. Nitro attestation infrastructure ─────────────────
        CertManager certManager = new CertManager();
        console.log("CertManager:", address(certManager));

        NitroProver prover = new NitroProver(certManager);
        console.log("NitroProver:", address(prover));

        uint256 maxAge = 365 days;
        // PCR-1/PCR-2: pass bytes32(0) to skip validation initially.
        // Populate from `nitro-cli describe-enclaves` after first deploy.
        bytes32 expectedPCR1 = vm.envOr("EXPECTED_PCR1", bytes32(0));
        bytes32 expectedPCR2 = vm.envOr("EXPECTED_PCR2", bytes32(0));
        NitroAttestationVerifier verifier = new NitroAttestationVerifier(address(prover), maxAge, expectedPCR1, expectedPCR2);
        console.log("NitroAttestationVerifier:", address(verifier));

        // ─── 2. Verify attestation, extract PCR0 + signer ───────
        (bool valid, bytes32 pcr0, address enclaveSigner) = verifier.verifyAttestation(attestationDoc);
        require(valid, "Attestation invalid");
        console.log("PCR0:");
        console.logBytes32(pcr0);
        console.log("Enclave signer:", enclaveSigner);

        // Cache cert chain (required for on-chain verification)
        verifier.verifyCerts(attestationDoc);

        // ─── 3. Oracle with real PCR0 ────────────────────────────
        // Galleon testnet: block.timestamp derives from DAA scores, lags up to 2h
        KaskadPriceOracle oracle = new KaskadPriceOracle(pcr0, address(verifier), 3 hours);
        console.log("KaskadPriceOracle:", address(oracle));

        oracle.registerEnclave(attestationDoc);
        console.log("Enclave registered on-chain (real Nitro attestation)");

        // ─── 4. Aggregators (4 assets, IGRA/KSKD stay on MockOracle) ─
        KaskadAggregatorV3 ethAgg  = new KaskadAggregatorV3(address(oracle), keccak256("ETH/USD"),  "ETH / USD");
        KaskadAggregatorV3 btcAgg  = new KaskadAggregatorV3(address(oracle), keccak256("BTC/USD"),  "BTC / USD");
        KaskadAggregatorV3 usdcAgg = new KaskadAggregatorV3(address(oracle), keccak256("USDC/USD"), "USDC / USD");
        KaskadAggregatorV3 kasAgg  = new KaskadAggregatorV3(address(oracle), keccak256("KAS/USD"),  "KAS / USD");

        console.log("ETH/USD  Aggregator:", address(ethAgg));
        console.log("BTC/USD  Aggregator:", address(btcAgg));
        console.log("USDC/USD Aggregator:", address(usdcAgg));
        console.log("KAS/USD  Aggregator:", address(kasAgg));

        // ─── 5. Router ───────────────────────────────────────────
        KaskadRouter router = new KaskadRouter(address(oracle), AAVE_POOL);
        console.log("KaskadRouter:", address(router));

        vm.stopBroadcast();
    }
}
