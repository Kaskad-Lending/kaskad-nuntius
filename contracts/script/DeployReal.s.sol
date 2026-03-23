// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/KaskadPriceOracle.sol";
import "../src/KaskadAggregatorV3.sol";
import "../src/NitroAttestationVerifier.sol";
import "nitro-prover/CertManager.sol";

contract DeployReal is Script {
    function run() external {
        bytes memory attestationDoc = vm.envBytes("ATTESTATION_DOC");

        vm.startBroadcast();

        // 1. Deploy CertManager
        CertManager certManager = new CertManager();
        console.log("CertManager deployed at:", address(certManager));

        // 2. Deploy NitroAttestationVerifier
        uint256 maxAge = 365 days; // Relaxed maxAge for testing
        NitroAttestationVerifier verifier = new NitroAttestationVerifier(address(certManager), maxAge);
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
        KaskadPriceOracle oracle = new KaskadPriceOracle(pcr0, address(verifier));
        console.log("KaskadPriceOracle deployed at:", address(oracle));

        // 4. Register the real AWS Enclave on-chain
        oracle.registerEnclave(attestationDoc);
        console.log("Real AWS Nitro Enclave registered successfully on Anvil!");

        vm.stopBroadcast();
    }
}
