// SPDX-License-Identifier: MIT
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
        certManager.initialize();
        console.log("CertManager deployed at:", address(certManager));

        NitroProver prover = new NitroProver(certManager);
        console.log("NitroProver deployed at:", address(prover));

        // Deploy NitroAttestationVerifier
        uint256 maxAge = 365 days; // 1 year for tests
        NitroAttestationVerifier verifier = new NitroAttestationVerifier(address(prover), maxAge);
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
        uint256 maxFutureTs = vm.envOr("MAX_FUTURE_TIMESTAMP", uint256(5 minutes));
        KaskadPriceOracle oracle = new KaskadPriceOracle(pcr0, address(verifier), maxFutureTs);
        console.log("KaskadPriceOracle deployed at:", address(oracle));

        // 4. Register the real AWS Enclave on-chain
        oracle.registerEnclave(attestationDoc);
        console.log("Real AWS Nitro Enclave registered successfully on Anvil!");

        vm.stopBroadcast();
    }
}
