// SPDX-License-Identifier: MIT
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
    /// @notice Marlin NitroProver instance (handles CBOR/COSE/P384 verification).
    NitroProver public immutable nitroProver;

    /// @notice Maximum age of attestation document in seconds.
    ///         Prevents replay of old attestations.
    uint256 public immutable maxAttestationAge;

    /// @notice PCR indices to verify (bitmask). We check PCR0 only by default.
    ///         PCR0 = enclave image measurement.
    bytes public pcrFlags;

    /// @param _nitroProver Address of deployed NitroProver contract
    /// @param _maxAge Maximum acceptable attestation age in seconds (e.g. 300 = 5 min)
    constructor(address _nitroProver, uint256 _maxAge) {
        nitroProver = NitroProver(_nitroProver);
        maxAttestationAge = _maxAge;

        // We only validate PCR0 (bit 0 set = 0x00000001).
        // PCR0 is 48 bytes (SHA-384).
        // The pcrFlags format: 4 bytes bitmask + 48 bytes per enabled PCR
        // We'll populate the expected PCR0 at verification time from the attestation itself
        // (the oracle contract checks pcr0 == expectedPCR0 separately)
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
        try nitroProver.verifyAttestation(attestationDoc, maxAttestationAge) returns (
            bytes memory enclaveKey,
            bytes memory /* userData */,
            bytes memory rawPcrs
        ) {
            // Extract PCR0 from the PCR map
            pcr0 = _extractPCR0(rawPcrs);

            // Derive Ethereum address from enclave public key
            enclaveAddress = _deriveAddress(enclaveKey);

            valid = true;
        } catch {
            valid = false;
            pcr0 = bytes32(0);
            enclaveAddress = address(0);
        }
    }

    /// @notice Verify certificates in the attestation (must be called before verifyAttestation on first use).
    ///         This caches the certificate chain in CertManager for cheaper subsequent verifications.
    /// @param attestationDoc Raw attestation document
    function verifyCerts(bytes calldata attestationDoc) external {
        nitroProver.verifyCerts(attestationDoc);
    }

    /// @dev Extract PCR0 from CBOR-encoded PCR map.
    ///      PCR map format: { 0: <48 bytes>, 1: <48 bytes>, ... }
    function _extractPCR0(bytes memory rawPcrs) internal view returns (bytes32) {
        bytes[2][] memory pcrs = CBORDecoding.decodeMapping(rawPcrs);

        for (uint i = 0; i < pcrs.length; i++) {
            // Find PCR index 0
            if (ByteParser.bytesToUint64(pcrs[i][0]) == 0) {
                bytes memory pcr0Bytes = pcrs[i][1];
                // PCR0 is 48 bytes (SHA-384). Pack first 32 bytes into bytes32.
                // The oracle contract will compare this with expectedPCR0.
                if (pcr0Bytes.length != 48) revert InvalidPCR0Length(pcr0Bytes.length);
                bytes32 result;
                assembly {
                    result := mload(add(pcr0Bytes, 32))
                }
                return result;
            }
        }
        revert PCR0NotFound();
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
