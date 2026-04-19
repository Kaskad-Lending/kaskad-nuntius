// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title KaskadPriceOracle
/// @notice TEE-backed price oracle. An enclave whose PCR0 matches the
///         expected value (set at deploy) signs individual price updates
///         with EIP-191; anyone can relay those updates to the chain. The
///         per-asset quorum commitment is set by an `admin` key at deploy
///         time via `registerAssets`. The admin role is purely a bootstrap
///         / rotation authority: it cannot sign prices, cannot bypass the
///         circuit breaker, cannot override the signer.
contract KaskadPriceOracle {
    using MessageHashUtils for bytes32;

    // ─── Types ───────────────────────────────────────────────────────────

    struct PriceData {
        uint256 price;           // fixed-point, 8 decimals
        uint256 timestamp;       // block.timestamp at update (for consumers/Aave staleness checks)
        uint256 signedTimestamp; // enclave exchange-server timestamp (for replay/ordering checks)
        uint8   numSources;      // number of sources used
        bytes32 sourcesHash;     // keccak256 commitment of source data
        uint80  roundId;         // incrementing round counter
    }

    /// @notice Per-asset quorum parameter. Kept as a struct for future
    ///         extensions (deviation / heartbeat) without a storage layout
    ///         migration.
    struct AssetParams {
        uint8 minSources;
    }

    // ─── Immutable Config ────────────────────────────────────────────────

    bytes32 public immutable expectedPCR0;
    IAttestationVerifier public immutable verifier;

    /// @notice Admin role for bootstrap operations (`registerAssets`). Set
    ///         at construction; cannot be changed. Compromising this key
    ///         lets the attacker re-submit quorum parameters but does NOT
    ///         let them sign prices — that still requires the enclave key.
    address public immutable admin;

    uint8 public constant DECIMALS = 8;
    uint16 public constant MAX_PRICE_CHANGE_BPS = 1500; // 15% regular cap

    /// @notice After `CIRCUIT_BREAKER_STALENESS` of on-chain silence the
    ///         circuit breaker loosens to `MAX_RESUME_CHANGE_BPS` (30%),
    ///         but ONLY if the update carries at least
    ///         `RESUME_QUORUM_MULTIPLIER × minSources` sources (audit H-4).
    uint16 public constant MAX_RESUME_CHANGE_BPS = 3000;
    uint256 public constant CIRCUIT_BREAKER_STALENESS = 4 hours;
    uint8 public constant RESUME_QUORUM_MULTIPLIER = 2;

    // ─── State ───────────────────────────────────────────────────────────

    /// @notice Grow-only set of enclave-attested signing addresses. A signer
    ///         is added on the first `registerEnclave` call that recovers
    ///         it from a valid PCR0-matching attestation. The set NEVER
    ///         shrinks — there is no revoke function. Rationale: an
    ///         attacker with a same-PCR attestation can add their own
    ///         signer (they could do that anyway — the image is
    ///         measured, not the builder), but cannot evict the legit
    ///         signer. Both signers produce identical prices because
    ///         they run identical measured code. A compromised key (off
    ///         the stated threat model — requires breaking AWS Nitro
    ///         isolation) requires redeploy with a new `expectedPCR0`.
    mapping(address => bool) public validSigner;

    /// @notice Count of addresses in `validSigner`. Used by
    ///         `registerAssets` to refuse a pre-bootstrap admin call and
    ///         to expose oracle-ready state to off-chain observers.
    uint256 public signerCount;

    mapping(bytes32 => PriceData) public latestPrices;
    mapping(bytes32 => mapping(uint80 => PriceData)) public priceHistory;
    mapping(bytes32 => uint80) public currentRound;

    /// @notice Per-asset quorum, keyed by keccak256(symbol). `minSources == 0`
    ///         means the asset has NOT been registered and `updatePrice`
    ///         for it will revert.
    mapping(bytes32 => AssetParams) public assetParams;

    /// @notice Ordered list of currently-registered asset ids. Used to
    ///         clear `assetParams` when the admin re-calls `registerAssets`
    ///         with a different set.
    bytes32[] private _registeredAssetIds;

    // ─── Events ──────────────────────────────────────────────────────────

    event EnclaveRegistered(address indexed signer, bytes32 pcr0, uint256 timestamp);
    event PriceUpdated(
        bytes32 indexed assetId,
        uint256 price,
        uint256 timestamp,
        uint8   numSources,
        uint80  roundId
    );
    event AssetsRegistered(address indexed admin, uint256 numAssets);

    // ─── Errors ──────────────────────────────────────────────────────────

    error InvalidAttestation();
    error PCR0Mismatch(bytes32 provided, bytes32 expected);
    error InvalidSignature();
    error StalePrice(uint256 provided, uint256 current);
    error NoEnclaveRegistered();
    error InsufficientSources();
    error PriceChangeExceedsLimit(uint256 changeBps, uint256 maxBps);
    error NoPriceData(bytes32 assetId);
    error AssetNotRegistered(bytes32 assetId);
    error AssetsUnsorted();
    error AssetsEmpty();
    error MismatchedLengths();
    error InvalidMinSources();
    error ResumeRequiresHigherQuorum(uint8 provided, uint8 required);
    error NotAdmin();
    error ZeroAddress();

    // ─── Constructor ─────────────────────────────────────────────────────

    constructor(bytes32 _expectedPCR0, address _verifier, address _admin) {
        if (_admin == address(0) || _verifier == address(0)) revert ZeroAddress();
        expectedPCR0 = _expectedPCR0;
        verifier = IAttestationVerifier(_verifier);
        admin = _admin;
    }

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    // ─── Enclave Registration (permissionless, grow-only) ────────────────

    /// @notice Register an enclave signer. Anyone can call — only a valid
    ///         attestation with the expected PCR0 succeeds. Each first-
    ///         time successful call ADDS the recovered address to the
    ///         valid-signer set; re-registering the same address is a
    ///         no-op.
    ///
    ///         Grow-only semantics close the grief-loop where an attacker
    ///         with a valid same-PCR attestation would otherwise ping-
    ///         pong `enclave.signer` and break legit relayer submissions.
    ///         With a set, both signers are valid concurrently, and
    ///         because they sign identical measured code they produce
    ///         identical prices — the set membership is a permission
    ///         token, not a price source.
    function registerEnclave(bytes calldata attestationDoc) external {
        (bool valid, bytes32 pcr0, address enclaveAddress) =
            verifier.verifyAttestation(attestationDoc);

        if (!valid) revert InvalidAttestation();
        if (pcr0 != expectedPCR0) revert PCR0Mismatch(pcr0, expectedPCR0);

        // Idempotent add. Without this guard a spam caller could inflate
        // `signerCount` and emit duplicate events for a no-op state
        // change.
        if (!validSigner[enclaveAddress]) {
            validSigner[enclaveAddress] = true;
            signerCount += 1;
            emit EnclaveRegistered(enclaveAddress, pcr0, block.timestamp);
        }
    }

    // ─── Asset-quorum registration (admin) ───────────────────────────────

    /// @notice Write the per-asset quorum commitment. Only callable by the
    ///         admin key set at construction. `ids` MUST be strictly
    ///         ascending (canonical order, no duplicates).
    /// @param ids        keccak256("ETH/USD"), ..., sorted ascending
    /// @param minSources per-asset quorum, each must be >= 1
    function registerAssets(
        bytes32[] calldata ids,
        uint8[] calldata minSources
    ) external onlyAdmin {
        if (signerCount == 0) revert NoEnclaveRegistered();
        if (ids.length == 0) revert AssetsEmpty();
        if (ids.length != minSources.length) revert MismatchedLengths();

        uint256 oldLen = _registeredAssetIds.length;
        for (uint256 i = 0; i < oldLen; i++) {
            delete assetParams[_registeredAssetIds[i]];
        }
        delete _registeredAssetIds;

        for (uint256 i = 0; i < ids.length; i++) {
            if (i > 0 && ids[i] <= ids[i - 1]) revert AssetsUnsorted();
            if (minSources[i] == 0) revert InvalidMinSources();
            assetParams[ids[i]] = AssetParams({minSources: minSources[i]});
            _registeredAssetIds.push(ids[i]);
        }

        emit AssetsRegistered(msg.sender, ids.length);
    }

    /// @notice Ordered list of currently-registered asset ids.
    function registeredAssetIds() external view returns (bytes32[] memory) {
        return _registeredAssetIds;
    }

    // ─── Core: Price Update ──────────────────────────────────────────────

    function updatePrice(
        bytes32 assetId,
        uint256 price,
        uint256 timestamp,
        uint8   numSources,
        bytes32 sourcesHash,
        bytes calldata signature
    ) external {
        if (signerCount == 0) revert NoEnclaveRegistered();

        uint8 minReq = assetParams[assetId].minSources;
        if (minReq == 0) revert AssetNotRegistered(assetId);
        if (numSources < minReq) revert InsufficientSources();

        _checkFreshnessAndBreaker(assetId, price, timestamp, numSources, minReq);
        _verifyPriceSignature(assetId, price, timestamp, numSources, sourcesHash, signature);
        _storePriceUpdate(assetId, price, timestamp, numSources, sourcesHash);
    }

    // ─── updatePrice internals (split to avoid stack-too-deep) ───────────

    function _checkFreshnessAndBreaker(
        bytes32 assetId,
        uint256 price,
        uint256 timestamp,
        uint8 numSources,
        uint8 minReq
    ) internal view {
        PriceData storage current = latestPrices[assetId];

        if (current.signedTimestamp > 0 && timestamp <= current.signedTimestamp) {
            revert StalePrice(timestamp, current.signedTimestamp);
        }

        if (current.price == 0) return;

        uint16 limit = MAX_PRICE_CHANGE_BPS;
        if (block.timestamp - current.timestamp >= CIRCUIT_BREAKER_STALENESS) {
            uint8 required = minReq * RESUME_QUORUM_MULTIPLIER;
            if (numSources < required) {
                revert ResumeRequiresHigherQuorum(numSources, required);
            }
            limit = MAX_RESUME_CHANGE_BPS;
        }

        uint256 changeBps;
        if (price > current.price) {
            changeBps = ((price - current.price) * 10000) / current.price;
        } else {
            changeBps = ((current.price - price) * 10000) / current.price;
        }
        if (changeBps > limit) revert PriceChangeExceedsLimit(changeBps, limit);
    }

    /// @dev Rebuilds the enclave's abi.encodePacked payload, applies
    ///      EIP-191 via `MessageHashUtils.toEthSignedMessageHash`, recovers
    ///      the signer, and reverts if it isn't a member of the valid-
    ///      signer set.
    function _verifyPriceSignature(
        bytes32 assetId,
        uint256 price,
        uint256 timestamp,
        uint8 numSources,
        bytes32 sourcesHash,
        bytes calldata signature
    ) internal view {
        bytes32 messageHash = keccak256(
            abi.encodePacked(assetId, price, timestamp, numSources, sourcesHash)
        );
        address recovered = ECDSA.recover(messageHash.toEthSignedMessageHash(), signature);
        if (!validSigner[recovered]) revert InvalidSignature();
    }

    function _storePriceUpdate(
        bytes32 assetId,
        uint256 price,
        uint256 timestamp,
        uint8 numSources,
        bytes32 sourcesHash
    ) internal {
        uint80 newRound = currentRound[assetId] + 1;

        PriceData storage stored = latestPrices[assetId];
        stored.price = price;
        stored.timestamp = block.timestamp;
        stored.signedTimestamp = timestamp;
        stored.numSources = numSources;
        stored.sourcesHash = sourcesHash;
        stored.roundId = newRound;

        priceHistory[assetId][newRound] = stored;
        currentRound[assetId] = newRound;

        emit PriceUpdated(assetId, price, timestamp, numSources, newRound);
    }

    // ─── Reads ───────────────────────────────────────────────────────────

    function getLatestPrice(bytes32 assetId)
        external
        view
        returns (uint256 price, uint256 timestamp, uint8 numSources, uint80 roundId)
    {
        PriceData storage data = latestPrices[assetId];
        if (data.timestamp == 0) revert NoPriceData(assetId);
        return (data.price, data.timestamp, data.numSources, data.roundId);
    }

    function getRoundData(bytes32 assetId, uint80 roundId)
        external
        view
        returns (uint256 price, uint256 timestamp, uint8 numSources)
    {
        PriceData storage data = priceHistory[assetId][roundId];
        return (data.price, data.timestamp, data.numSources);
    }

    /// @notice Convenience alias for the public `validSigner` mapping.
    ///         Off-chain clients verifying a signature should recover the
    ///         ECDSA address locally and call this to check membership —
    ///         there is no single "oracleSigner" anymore, the set may
    ///         contain multiple addresses.
    function isValidSigner(address who) external view returns (bool) {
        return validSigner[who];
    }
}

/// @title IAttestationVerifier
/// @notice Interface for TEE attestation verification.
interface IAttestationVerifier {
    function verifyAttestation(bytes calldata attestationDoc)
        external
        view
        returns (bool valid, bytes32 pcr0, address enclaveAddress);
}
