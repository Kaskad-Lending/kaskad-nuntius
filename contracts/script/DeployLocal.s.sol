// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "./Deploy.s.sol";
import "../test/mocks/MockVerifiers.sol";

/// @notice Local/anvil deploy. Swaps the Nitro verifier stack for a
///         `MockAttestationVerifier` that accepts `hex"00"` and returns
///         a predetermined (pcr0, signer) pair. Everything else —
///         `registerEnclave`, `registerAssets`, aggregator deployment —
///         is inherited from `Deploy`, so local flow matches prod flow.
///
/// Required env:
///   DEPLOYER_KEY    — uint256 private key (or `--private-key` on CLI)
///   ORACLE_ADMIN    — address with `registerAssets` authority
///   ORACLE_SIGNER   — (optional) enclave-signer address the mock returns.
///                     Defaults to Anvil account #1.
contract DeployLocal is Deploy {
    /// @notice Fake PCR0 — must match what `MockAttestationVerifier`
    ///         returns. Local-only; prod derives the real one from the
    ///         attestation document.
    bytes32 constant LOCAL_PCR0 = keccak256("kaskad-oracle:local");

    address constant ANVIL_ACCOUNT_1 = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;

    function _buildVerifier() internal override returns (IAttestationVerifier) {
        address signer = vm.envOr("ORACLE_SIGNER", ANVIL_ACCOUNT_1);
        MockAttestationVerifier verifier = new MockAttestationVerifier(LOCAL_PCR0, signer);
        console.log("MockAttestationVerifier:", address(verifier));
        console.log("Mock enclave signer:", signer);
        return IAttestationVerifier(address(verifier));
    }

    function _getAttestationDoc() internal pure override returns (bytes memory) {
        return hex"00";
    }

    function _cacheCerts(IAttestationVerifier, bytes memory) internal override {
        // Mock verifier has no cert chain to cache.
    }

    function _extractPCR0(IAttestationVerifier, bytes memory)
        internal
        pure
        override
        returns (bytes32)
    {
        return LOCAL_PCR0;
    }
}
