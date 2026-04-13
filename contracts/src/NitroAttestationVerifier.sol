// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {NitroProver} from "nitro-prover/NitroProver.sol";
import {CertManager} from "nitro-prover/CertManager.sol";
import {CBORDecoding} from "marlinprotocol/solidity-cbor/CBORDecoding.sol";
import {ByteParser} from "marlinprotocol/solidity-cbor/ByteParser.sol";

import "../src/KaskadPriceOracle.sol";

/// @title NitroAttestationVerifier
/// @notice On-chain verification of AWS Nitro Enclave attestation documents.
///         Wraps Marlin's NitroProver (MIT) to implement our IAttestationVerifier.
///
/// Flow:
///   1. Enclave generates keypair + requests attestation from NSM
///   2. Anyone calls registerEnclave(attestationDoc) on KaskadPriceOracle
///   3. Oracle calls this verifier which:
///      a) Verifies COSE_Sign1 signature (P-384/ES384)
///      b) Validates certificate chain (AWS Root CA → Enclave cert)
///      c) Checks attestation freshness (max_age)
///      d) Extracts PCR0 and enclave public key
///      e) Derives Ethereum address from enclave key
///   4. Returns (valid, pcr0, enclaveAddress) to the oracle contract
contract NitroAttestationVerifier is IAttestationVerifier {
    error InvalidPCR0Length(uint256 length);
    error PCR0NotFound();
    error InvalidPublicKeyLength(uint256 length);
    error PCR1Mismatch();
    error PCR2Mismatch();

    /// @notice Marlin NitroProver instance (handles CBOR/COSE/P384 verification).
    NitroProver public immutable nitroProver;

    /// @notice Maximum age of attestation document in seconds.
    uint256 public immutable maxAttestationAge;

    /// @notice Expected PCR-1 (kernel hash) and PCR-2 (application hash).
    ///         PCR-0 is checked by KaskadPriceOracle. PCR-1 and PCR-2 are checked here.
    ///         Set to bytes32(0) to skip validation (e.g. during development).
    bytes32 public immutable expectedPCR1;
    bytes32 public immutable expectedPCR2;

    bytes public pcrFlags;

    /// @param _nitroProver Address of deployed NitroProver contract
    /// @param _maxAge Maximum acceptable attestation age in seconds
    /// @param _expectedPCR1 Expected PCR-1 hash (bytes32(0) to skip)
    /// @param _expectedPCR2 Expected PCR-2 hash (bytes32(0) to skip)
    constructor(address _nitroProver, uint256 _maxAge, bytes32 _expectedPCR1, bytes32 _expectedPCR2) {
        nitroProver = NitroProver(_nitroProver);
        maxAttestationAge = _maxAge;
        expectedPCR1 = _expectedPCR1;
        expectedPCR2 = _expectedPCR2;
        pcrFlags = hex"00000001";
    }

    /// @notice Verify a Nitro attestation document.
    /// @param attestationDoc Raw CBOR-encoded COSE_Sign1 attestation from NSM
    /// @return valid Whether the attestation is cryptographically valid
    /// @return pcr0 PCR0 measurement (48 bytes sha384, packed into bytes32 = first 32 bytes)
    /// @return enclaveAddress Ethereum address derived from the enclave's public key
    function verifyAttestation(bytes calldata attestationDoc)
        external
        view
        override
        returns (bool valid, bytes32 pcr0, address enclaveAddress)
    {
        (bytes memory enclaveKey, , bytes memory rawPcrs) =
            nitroProver.verifyAttestation(attestationDoc, maxAttestationAge);

        // Extract and validate all PCRs
        bytes32 pcr1;
        bytes32 pcr2;
        (pcr0, pcr1, pcr2) = _extractPCRs(rawPcrs);

        // PCR-1 and PCR-2 validated here (PCR-0 validated by KaskadPriceOracle)
        if (expectedPCR1 != bytes32(0) && pcr1 != expectedPCR1) revert PCR1Mismatch();
        if (expectedPCR2 != bytes32(0) && pcr2 != expectedPCR2) revert PCR2Mismatch();

        // Derive Ethereum address from enclave public key
        enclaveAddress = _deriveAddress(enclaveKey);

        valid = true;
    }

    /// @notice Verify certificates in the attestation (must be called before verifyAttestation on first use).
    ///         This caches the certificate chain in CertManager for cheaper subsequent verifications.
    /// @param attestationDoc Raw attestation document
    function verifyCerts(bytes calldata attestationDoc) external {
        nitroProver.verifyCerts(attestationDoc);
    }

    /// @dev Extract PCR-0, PCR-1, PCR-2 from CBOR-encoded PCR map.
    ///      PCR map format: { 0: <48 bytes>, 1: <48 bytes>, 2: <48 bytes>, ... }
    ///      Each 48-byte SHA-384 hash is truncated to bytes32 (first 32 bytes).
    function _extractPCRs(bytes memory rawPcrs) internal view returns (bytes32 pcr0, bytes32 pcr1, bytes32 pcr2) {
        bytes[2][] memory pcrs = CBORDecoding.decodeMapping(rawPcrs);
        bool found0;

        for (uint i = 0; i < pcrs.length; i++) {
            uint64 idx = ByteParser.bytesToUint64(pcrs[i][0]);
            if (idx <= 2) {
                bytes memory pcrBytes = pcrs[i][1];
                if (pcrBytes.length != 48) revert InvalidPCR0Length(pcrBytes.length);
                bytes32 packed;
                assembly {
                    packed := mload(add(pcrBytes, 32))
                }
                if (idx == 0) { pcr0 = packed; found0 = true; }
                else if (idx == 1) { pcr1 = packed; }
                else if (idx == 2) { pcr2 = packed; }
            }
        }
        if (!found0) revert PCR0NotFound();
    }

    /// @dev Derive Ethereum address from enclave public key.
    ///      The enclave key from Nitro is a raw public key (65 bytes: 0x04 + x + y for uncompressed,
    ///      or a different format depending on NSM configuration).
    function _deriveAddress(bytes memory publicKey) internal pure returns (address) {
        // Standard Ethereum derivation: keccak256(pubkey_uncompressed[1:]) → last 20 bytes
        if (publicKey.length == 65) {
            // Uncompressed: skip 0x04 prefix
            bytes memory xy = new bytes(64);
            for (uint i = 0; i < 64; i++) {
                xy[i] = publicKey[i + 1];
            }
            return address(uint160(uint256(keccak256(xy))));
        } else if (publicKey.length == 64) {
            // Already stripped prefix
            return address(uint160(uint256(keccak256(publicKey))));
        } else {
            revert InvalidPublicKeyLength(publicKey.length);
        }
    }
}
