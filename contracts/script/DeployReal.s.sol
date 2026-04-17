// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/KaskadPriceOracle.sol";
import "../src/KaskadAggregatorV3.sol";
import "../src/NitroAttestationVerifier.sol";
import "nitro-prover/CertManager.sol";

import {NitroProver} from "nitro-prover/NitroProver.sol";

contract DeployReal is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        bytes memory attestationDoc = vm.envBytes("ATTESTATION_DOC");

        vm.startBroadcast(deployerKey);

        // Deploy CertManager
        CertManager certManager = new CertManager();
        console.log("CertManager deployed at:", address(certManager));

        NitroProver prover = new NitroProver(certManager);
        console.log("NitroProver deployed at:", address(prover));

        // Deploy NitroAttestationVerifier. `MAX_ATTESTATION_AGE` is a
        // constant inside the verifier (4 h, see audit H-1). PCR-1 and
        // PCR-2 MUST be non-zero (audit H-7).
        bytes32 expectedPCR1 = vm.envBytes32("EXPECTED_PCR1");
        bytes32 expectedPCR2 = vm.envBytes32("EXPECTED_PCR2");
        NitroAttestationVerifier verifier = new NitroAttestationVerifier(address(prover), expectedPCR1, expectedPCR2);
        console.log("NitroAttestationVerifier deployed at:", address(verifier));

        // Extract real pcr0 and signer from the doc by doing a view call
        (bool valid, bytes32 pcr0, address enclaveSigner) = verifier.verifyAttestation(attestationDoc);
        require(valid, "Attestation is not valid! (Root CA signature check failed)");
        console.log("Real AWS Nitro PCR0:");
        console.logBytes32(pcr0);
        console.log("Real Enclave Signer:", enclaveSigner);

        // We MUST verify certs to cache the chain before the smart contract's state modifies (it's required by the oracle)
        verifier.verifyCerts(attestationDoc);

        // 3. Deploy Oracle with REAL PCR0
        address admin = vm.envAddress("ORACLE_ADMIN");
        KaskadPriceOracle oracle = new KaskadPriceOracle(pcr0, address(verifier), admin);
        console.log("KaskadPriceOracle deployed at:", address(oracle));
        console.log("Admin (can call registerAssets):", admin);

        // 4. Register the real AWS Enclave on-chain
        oracle.registerEnclave(attestationDoc);
        console.log("Real AWS Nitro Enclave registered successfully on Anvil!");

        vm.stopBroadcast();
    }
}
