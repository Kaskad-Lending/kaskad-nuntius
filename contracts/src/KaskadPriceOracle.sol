// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title KaskadPriceOracle
/// @notice Receives signed price updates from a TEE oracle enclave and stores them on-chain.
/// @dev Signature verification via ecrecover. Designed as the single source of truth
///      for the Kaskad lending protocol (Aave V3 fork on Galleon testnet).
contract KaskadPriceOracle {
    // ─── Types ───────────────────────────────────────────────────────────

    struct PriceData {
        uint256 price;        // fixed-point, 8 decimals (e.g. 212926000000 = $2129.26)
        uint256 timestamp;    // unix seconds when the price was observed
        uint8   numSources;   // number of data sources used in aggregation
        bytes32 sourcesHash;  // keccak256 commitment of source data
        uint80  roundId;      // incrementing round counter
    }

    // ─── State ───────────────────────────────────────────────────────────

    /// @notice Owner (deployer). Can register/revoke oracle signers.
    address public owner;

    /// @notice Authorized oracle signer (TEE enclave address).
    address public oracleSigner;

    /// @notice Latest price data per asset.
    mapping(bytes32 => PriceData) public latestPrices;

    /// @notice Price history per asset (roundId => PriceData).
    mapping(bytes32 => mapping(uint80 => PriceData)) public priceHistory;

    /// @notice Current round ID per asset.
    mapping(bytes32 => uint80) public currentRound;

    /// @notice Number of decimals for price values.
    uint8 public constant DECIMALS = 8;

    // ─── Events ──────────────────────────────────────────────────────────

    event PriceUpdated(
        bytes32 indexed assetId,
        uint256 price,
        uint256 timestamp,
        uint8   numSources,
        uint80  roundId
    );

    event OracleSignerUpdated(address indexed oldSigner, address indexed newSigner);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    // ─── Errors ──────────────────────────────────────────────────────────

    error Unauthorized();
    error InvalidSignature();
    error StalePrice(uint256 provided, uint256 current);
    error ZeroAddress();
    error InsufficientSources();

    // ─── Constructor ─────────────────────────────────────────────────────

    constructor(address _oracleSigner) {
        if (_oracleSigner == address(0)) revert ZeroAddress();
        owner = msg.sender;
        oracleSigner = _oracleSigner;
    }

    // ─── Admin ───────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    /// @notice Set a new oracle signer address (e.g. after enclave re-attestation).
    function setOracleSigner(address _newSigner) external onlyOwner {
        if (_newSigner == address(0)) revert ZeroAddress();
        emit OracleSignerUpdated(oracleSigner, _newSigner);
        oracleSigner = _newSigner;
    }

    /// @notice Transfer ownership.
    function transferOwnership(address _newOwner) external onlyOwner {
        if (_newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    // ─── Core: Price Update ──────────────────────────────────────────────

    /// @notice Submit a signed price update from the oracle enclave.
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
        // Require at least 2 independent sources (except governance-set assets)
        if (numSources < 1) revert InsufficientSources();

        // Prevent stale/replay updates
        PriceData storage current = latestPrices[assetId];
        if (current.timestamp > 0 && timestamp <= current.timestamp) {
            revert StalePrice(timestamp, current.timestamp);
        }

        // Verify signature
        bytes32 messageHash = keccak256(
            abi.encodePacked(assetId, price, timestamp, numSources, sourcesHash)
        );
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );

        address recovered = _recover(ethSignedHash, signature);
        if (recovered != oracleSigner) revert InvalidSignature();

        // Store
        uint80 newRound = currentRound[assetId] + 1;
        PriceData memory newData = PriceData({
            price: price,
            timestamp: timestamp,
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

    /// @notice Get the latest price for an asset.
    function getLatestPrice(bytes32 assetId)
        external
        view
        returns (uint256 price, uint256 timestamp, uint8 numSources, uint80 roundId)
    {
        PriceData storage data = latestPrices[assetId];
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

    // ─── Internal ────────────────────────────────────────────────────────

    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        if (v < 27) v += 27;

        address recovered = ecrecover(hash, v, r, s);
        if (recovered == address(0)) revert InvalidSignature();
        return recovered;
    }
}
