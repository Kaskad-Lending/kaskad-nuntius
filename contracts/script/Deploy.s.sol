// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/KaskadPriceOracle.sol";
import "../src/KaskadAggregatorV3.sol";
import "../src/NitroAttestationVerifier.sol";
import "nitro-prover/CertManager.sol";

import {NitroProver} from "nitro-prover/NitroProver.sol";

/// @notice Production deploy: real AWS Nitro attestation + full
///         `registerEnclave` + `registerAssets` so the oracle is usable
///         immediately after the script finishes. Override the hooks in
///         `DeployLocal` to swap the verifier for a mock on anvil.
///
/// Required env:
///   DEPLOYER_KEY         — uint256 private key (optional if `--private-key` passed)
///   ORACLE_ADMIN         — address with `registerAssets` authority
///   ATTESTATION_DOC      — raw Nitro attestation bytes (CBOR COSE_Sign1)
///   EXPECTED_PCR1        — bytes32 kernel hash baked into verifier
///   EXPECTED_PCR2        — bytes32 application hash baked into verifier
contract Deploy is Script {
    // ─── Hooks (overridden in DeployLocal) ────────────────────────────────

    /// @notice Deploy the attestation verifier stack. Prod: CertManager +
    ///         NitroProver + NitroAttestationVerifier with env-supplied
    ///         PCR1/PCR2. Local: MockAttestationVerifier.
    function _buildVerifier() internal virtual returns (IAttestationVerifier) {
        CertManager certManager = new CertManager();
        console.log("CertManager:", address(certManager));

        NitroProver prover = new NitroProver(certManager);
        console.log("NitroProver:", address(prover));

        bytes32 expectedPCR1 = vm.envBytes32("EXPECTED_PCR1");
        bytes32 expectedPCR2 = vm.envBytes32("EXPECTED_PCR2");
        NitroAttestationVerifier verifier =
            new NitroAttestationVerifier(address(prover), expectedPCR1, expectedPCR2);
        console.log("NitroAttestationVerifier:", address(verifier));
        return IAttestationVerifier(address(verifier));
    }

    /// @notice Return the attestation document used for `registerEnclave`.
    ///         Prod: loaded from env. Local: stub bytes accepted by mock.
    function _getAttestationDoc() internal virtual returns (bytes memory) {
        return vm.envBytes("ATTESTATION_DOC");
    }

    /// @notice Cache the certificate chain inside the verifier so the
    ///         subsequent on-chain `verifyAttestation` in `registerEnclave`
    ///         is cheap. Prod: calls `verifyCerts`. Local: no-op.
    function _cacheCerts(IAttestationVerifier verifier, bytes memory doc) internal virtual {
        NitroAttestationVerifier(address(verifier)).verifyCerts(doc);
    }

    /// @notice Extract the PCR0 that the oracle contract should be bound
    ///         to. Prod: dry-run `verifyAttestation` to read it out of the
    ///         attestation doc. Local: a compile-time constant that the
    ///         mock verifier is also constructed with.
    function _extractPCR0(IAttestationVerifier verifier, bytes memory doc)
        internal
        virtual
        returns (bytes32)
    {
        (bool valid, bytes32 pcr0, address enclaveSigner) = verifier.verifyAttestation(doc);
        require(valid, "Attestation invalid (Root CA signature / PCR1 / PCR2 mismatch)");
        console.log("Real AWS Nitro PCR0:");
        console.logBytes32(pcr0);
        console.log("Real Enclave Signer:", enclaveSigner);
        return pcr0;
    }

    // ─── Static config (shared by prod + local) ───────────────────────────

    /// @notice Asset registration commitment. IDs are `keccak256(symbol)`
    ///         and MUST be in strictly ascending byte order — the contract
    ///         enforces canonical ordering in `registerAssets`.
    ///         `min_sources` mirrors `config/assets.json` (baked into PCR0).
    function _getAssets()
        internal
        pure
        virtual
        returns (bytes32[] memory ids, uint8[] memory minSources)
    {
        ids = new bytes32[](5);
        minSources = new uint8[](5);

        // Sorted ascending — see `cast keccak` output:
        //   0x0b43…6e45  ETH/USD
        //   0x4db2…8273  IGRA/USD
        //   0xb445…5cd2  KAS/USD
        //   0xee62…6489  BTC/USD
        //   0xff06…b7ef  USDC/USD
        ids[0] = keccak256("ETH/USD");   minSources[0] = 3;
        ids[1] = keccak256("IGRA/USD");  minSources[1] = 1;
        ids[2] = keccak256("KAS/USD");   minSources[2] = 3;
        ids[3] = keccak256("BTC/USD");   minSources[3] = 3;
        ids[4] = keccak256("USDC/USD"); minSources[4] = 2;
    }

    // ─── Entrypoint ───────────────────────────────────────────────────────

    function run() external {
        uint256 key = vm.envOr("DEPLOYER_KEY", uint256(0));
        if (key != 0) {
            vm.startBroadcast(key);
        } else {
            vm.startBroadcast();
        }

        // 1. Verifier stack
        IAttestationVerifier verifier = _buildVerifier();

        // 2. Attestation doc
        bytes memory attestationDoc = _getAttestationDoc();

        // 3. Cache certs so on-chain verifyAttestation is cheap (prod only)
        _cacheCerts(verifier, attestationDoc);

        // 4. Pin PCR0 — deployed oracle will only accept this image
        bytes32 pcr0 = _extractPCR0(verifier, attestationDoc);

        // 5. Oracle
        address admin = vm.envAddress("ORACLE_ADMIN");
        KaskadPriceOracle oracle = new KaskadPriceOracle(pcr0, address(verifier), admin);
        console.log("KaskadPriceOracle deployed at:", address(oracle));
        console.log("Admin (can call registerAssets):", admin);

        // 6. Register the enclave signer (permissionless; grow-only set)
        oracle.registerEnclave(attestationDoc);
        console.log("Enclave registered on-chain");

        // 7. Register asset quorum commitment — REQUIRED before any
        //    `updatePrice` will succeed. Must be called by `admin`.
        (bytes32[] memory ids, uint8[] memory minSources) = _getAssets();
        oracle.registerAssets(ids, minSources);
        console.log("Registered assets:", ids.length);

        // 8. Per-asset Chainlink-compat wrappers
        _deployAggregators(address(oracle));

        vm.stopBroadcast();
    }

    function _deployAggregators(address oracle) internal {
        KaskadAggregatorV3 ethAgg  = new KaskadAggregatorV3(oracle, keccak256("ETH/USD"),  "ETH / USD");
        KaskadAggregatorV3 btcAgg  = new KaskadAggregatorV3(oracle, keccak256("BTC/USD"),  "BTC / USD");
        KaskadAggregatorV3 kasAgg  = new KaskadAggregatorV3(oracle, keccak256("KAS/USD"),  "KAS / USD");
        KaskadAggregatorV3 usdcAgg = new KaskadAggregatorV3(oracle, keccak256("USDC/USD"), "USDC / USD");
        KaskadAggregatorV3 igraAgg = new KaskadAggregatorV3(oracle, keccak256("IGRA/USD"), "IGRA / USD");

        console.log("ETH/USD Aggregator:", address(ethAgg));
        console.log("BTC/USD Aggregator:", address(btcAgg));
        console.log("KAS/USD Aggregator:", address(kasAgg));
        console.log("USDC/USD Aggregator:", address(usdcAgg));
        console.log("IGRA/USD Aggregator:", address(igraAgg));
    }
}
