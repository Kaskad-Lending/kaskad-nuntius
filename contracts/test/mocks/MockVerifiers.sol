// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../src/KaskadPriceOracle.sol";

/// @title MockAttestationVerifier
/// @notice Mock verifier for testing. Accepts any attestation and returns
///         pre-configured PCR0 + signer address.
///         NEVER deploy this in production — it bypasses all security.
contract MockAttestationVerifier is IAttestationVerifier {
    bytes32 public pcr0;
    address public enclaveAddr;

    constructor(bytes32 _pcr0, address _enclaveAddr) {
        pcr0 = _pcr0;
        enclaveAddr = _enclaveAddr;
    }

    function verifyAttestation(bytes calldata)
        external
        view
        override
        returns (bool valid, bytes32 _pcr0, address _enclaveAddress)
    {
        return (true, pcr0, enclaveAddr);
    }
}

/// @title FailingAttestationVerifier
/// @notice Always-failing verifier for negative tests.
contract FailingAttestationVerifier is IAttestationVerifier {
    function verifyAttestation(bytes calldata)
        external
        pure
        override
        returns (bool valid, bytes32 _pcr0, address _enclaveAddress)
    {
        return (false, bytes32(0), address(0));
    }
}

/// @title WrongPCR0Verifier
/// @notice Returns valid attestation but with wrong PCR0 — tests PCR0 mismatch.
contract WrongPCR0Verifier is IAttestationVerifier {
    address public enclaveAddr;

    constructor(address _enclaveAddr) {
        enclaveAddr = _enclaveAddr;
    }

    function verifyAttestation(bytes calldata)
        external
        view
        override
        returns (bool valid, bytes32 _pcr0, address _enclaveAddress)
    {
        return (true, bytes32(uint256(0xDEAD)), enclaveAddr);
    }
}
