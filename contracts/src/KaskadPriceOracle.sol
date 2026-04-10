// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title KaskadPriceOracle (Permissionless)
/// @notice Fully permissionless price oracle. No owner, no admin.
///         Enclave registers itself via TEE attestation proof.
///         Only code with the correct PCR0 hash can become the oracle signer.
contract KaskadPriceOracle {
    // ─── Types ───────────────────────────────────────────────────────────

    struct PriceData {
        uint256 price;           // fixed-point, 8 decimals
        uint256 timestamp;       // block.timestamp at update (for consumers/Aave staleness checks)
        uint256 signedTimestamp;  // enclave exchange-server timestamp (for replay/ordering checks)
        uint8   numSources;      // number of sources used
        bytes32 sourcesHash;     // keccak256 commitment of source data
        uint80  roundId;         // incrementing round counter
    }

    struct EnclaveInfo {
        address signer;           // derived ethereum address
        uint256 registeredAt;     // block.timestamp of registration
        bytes32 pcr0;             // enclave image hash
        bool    active;           // currently active
    }

    // ─── Immutable Config ────────────────────────────────────────────────

    /// @notice Expected enclave image hash. Set at deploy, NEVER changes.
    ///         This is the sha384 hash of the Docker image → EIF build.
    ///         Anyone can reproduce: build the same Dockerfile → get the same PCR0.
    bytes32 public immutable expectedPCR0;

    /// @notice Address of the attestation verifier contract.
    ///         Immutable — cannot be changed after deployment.
    IAttestationVerifier public immutable verifier;

    /// @notice Number of decimals for price values.
    uint8 public constant DECIMALS = 8;

    /// @notice Maximum price change per update in basis points (circuit breaker).
    ///         If a price moves more than this in a single update, the update is rejected.
    ///         Protects against flash crashes and oracle manipulation.
    uint16 public constant MAX_PRICE_CHANGE_BPS = 1500; // 15%

    /// @notice If the last update is older than this, skip the circuit breaker.
    ///         Prevents permanent asset lockout after extended downtime.
    uint256 public constant CIRCUIT_BREAKER_STALENESS = 4 hours;

    // ─── State ───────────────────────────────────────────────────────────

    /// @notice Currently registered enclave.
    EnclaveInfo public enclave;

    /// @notice Latest price data per asset.
    mapping(bytes32 => PriceData) public latestPrices;

    /// @notice Price history per asset (roundId => PriceData).
    mapping(bytes32 => mapping(uint80 => PriceData)) public priceHistory;

    /// @notice Current round ID per asset.
    mapping(bytes32 => uint80) public currentRound;

    // ─── Events ──────────────────────────────────────────────────────────

    event EnclaveRegistered(
        address indexed signer,
        bytes32 pcr0,
        uint256 timestamp
    );

    event PriceUpdated(
        bytes32 indexed assetId,
        uint256 price,
        uint256 timestamp,
        uint8   numSources,
        uint80  roundId
    );

    // ─── Errors ──────────────────────────────────────────────────────────

    error InvalidAttestation();
    error PCR0Mismatch(bytes32 provided, bytes32 expected);
    error InvalidSignature();
    error StalePrice(uint256 provided, uint256 current);
    error NoEnclaveRegistered();
    error InsufficientSources();
    error PriceChangeExceedsLimit(uint256 changeBps, uint256 maxBps);
    error NoPriceData(bytes32 assetId);

    // ─── Constructor ─────────────────────────────────────────────────────

    /// @param _expectedPCR0  The expected enclave image hash. IMMUTABLE.
    /// @param _verifier      Address of the attestation verifier. IMMUTABLE.
    constructor(bytes32 _expectedPCR0, address _verifier) {
        expectedPCR0 = _expectedPCR0;
        verifier = IAttestationVerifier(_verifier);
    }

    // NO owner. NO admin. NO setOracleSigner(). NO transferOwnership().

    // ─── Enclave Registration (permissionless) ───────────────────────────

    /// @notice Register an enclave as the oracle signer.
    ///         Anyone can call this, but only a valid attestation from an
    ///         enclave running the expected code (PCR0) will succeed.
    /// @param attestationDoc  Raw attestation document from TEE (CBOR-encoded COSE_Sign1 for Nitro)
    function registerEnclave(bytes calldata attestationDoc) external {
        // 1. Verify attestation document via the verifier contract
        (
            bool valid,
            bytes32 pcr0,
            address enclaveAddress
        ) = verifier.verifyAttestation(attestationDoc);

        if (!valid) revert InvalidAttestation();

        // 2. Check PCR0 matches our expected enclave image
        if (pcr0 != expectedPCR0) revert PCR0Mismatch(pcr0, expectedPCR0);

        // 3. Register the enclave signer
        enclave = EnclaveInfo({
            signer: enclaveAddress,
            registeredAt: block.timestamp,
            pcr0: pcr0,
            active: true
        });

        emit EnclaveRegistered(enclaveAddress, pcr0, block.timestamp);
    }

    // ─── Core: Price Update ──────────────────────────────────────────────

    /// @notice Submit a signed price update from the registered enclave.
    /// @param assetId     keccak256 of the asset symbol (e.g. keccak256("ETH/USD"))
    /// @param price       price in fixed-point with 8 decimals
    /// @param timestamp   unix timestamp of the observation
    /// @param numSources  number of data sources used
    /// @param sourcesHash keccak256 commitment of the sources and their values
    /// @param signature   65-byte ECDSA signature (r, s, v)
    function updatePrice(
        bytes32 assetId,
        uint256 price,
        uint256 timestamp,
        uint8   numSources,
        bytes32 sourcesHash,
        bytes calldata signature
    ) external {
        // Must have a registered enclave
        if (!enclave.active) revert NoEnclaveRegistered();

        // Require at least 1 source
        if (numSources < 1) revert InsufficientSources();

        PriceData storage current = latestPrices[assetId];

        // Prevent stale/replay updates (compare enclave-signed timestamps for ordering)
        if (current.signedTimestamp > 0 && timestamp <= current.signedTimestamp) {
            revert StalePrice(timestamp, current.signedTimestamp);
        }

        // Circuit breaker: reject extreme price changes.
        // Bypassed if the last update is stale (prevents permanent asset lockout after downtime).
        // Uses block.timestamp for staleness (consistent with on-chain time).
        if (current.price > 0 && block.timestamp - current.timestamp < CIRCUIT_BREAKER_STALENESS) {
            uint256 changeBps;
            if (price > current.price) {
                changeBps = ((price - current.price) * 10000) / current.price;
            } else {
                changeBps = ((current.price - price) * 10000) / current.price;
            }
            if (changeBps > MAX_PRICE_CHANGE_BPS) {
                revert PriceChangeExceedsLimit(changeBps, MAX_PRICE_CHANGE_BPS);
            }
        }

        // Verify signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(assetId, price, timestamp, numSources, sourcesHash)
        );
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );

        address recovered = ECDSA.recover(ethSignedHash, signature);
        if (recovered != enclave.signer) revert InvalidSignature();

        // Store — timestamp = block.timestamp for consumers (Aave staleness),
        // signedTimestamp = enclave exchange-server time for replay/ordering.
        uint80 newRound = currentRound[assetId] + 1;
        PriceData memory newData = PriceData({
            price: price,
            timestamp: block.timestamp,
            signedTimestamp: timestamp,
            numSources: numSources,
            sourcesHash: sourcesHash,
            roundId: newRound
        });

        latestPrices[assetId] = newData;
        priceHistory[assetId][newRound] = newData;
        currentRound[assetId] = newRound;

        emit PriceUpdated(assetId, price, timestamp, numSources, newRound);
    }

    // ─── Reads ───────────────────────────────────────────────────────────

    /// @notice Get the latest price for an asset. Reverts if no price has been set.
    function getLatestPrice(bytes32 assetId)
        external
        view
        returns (uint256 price, uint256 timestamp, uint8 numSources, uint80 roundId)
    {
        PriceData storage data = latestPrices[assetId];
        if (data.timestamp == 0) revert NoPriceData(assetId);
        return (data.price, data.timestamp, data.numSources, data.roundId);
    }

    /// @notice Get a historical price by round ID.
    function getRoundData(bytes32 assetId, uint80 roundId)
        external
        view
        returns (uint256 price, uint256 timestamp, uint8 numSources)
    {
        PriceData storage data = priceHistory[assetId][roundId];
        return (data.price, data.timestamp, data.numSources);
    }

    /// @notice Get the active enclave signer address.
    function oracleSigner() external view returns (address) {
        return enclave.signer;
    }

}

/// @title IAttestationVerifier
/// @notice Interface for TEE attestation verification.
///         Implementations: NitroVerifier (AWS), TDXVerifier (Intel), MockVerifier (testing).
interface IAttestationVerifier {
    /// @notice Verify a TEE attestation document.
    /// @param attestationDoc Raw attestation bytes
    /// @return valid          Whether the attestation is cryptographically valid
    /// @return pcr0           The enclave image measurement hash
    /// @return enclaveAddress The Ethereum address derived from the enclave's key
    function verifyAttestation(bytes calldata attestationDoc)
        external
        view
        returns (bool valid, bytes32 pcr0, address enclaveAddress);
}
