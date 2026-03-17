// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./KaskadPriceOracle.sol";

/// @title KaskadAggregatorV3
/// @notice Chainlink IAggregatorV3Interface-compatible wrapper around KaskadPriceOracle.
/// @dev Deploy one instance per asset. Allows Aave V3 (and other protocols expecting
///      Chainlink-style oracles) to read Kaskad oracle prices without modifications.
contract KaskadAggregatorV3 {
    KaskadPriceOracle public immutable oracle;
    bytes32 public immutable assetId;
    string public description;
    uint8 public constant decimals = 8;
    uint256 public constant version = 1;

    constructor(address _oracle, bytes32 _assetId, string memory _description) {
        oracle = KaskadPriceOracle(_oracle);
        assetId = _assetId;
        description = _description;
    }

    /// @notice Chainlink-compatible latest round data.
    function latestRoundData()
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        (uint256 price, uint256 timestamp, , uint80 round) = oracle.getLatestPrice(assetId);
        return (
            round,
            int256(price),
            timestamp,
            timestamp,
            round
        );
    }

    /// @notice Chainlink-compatible historical round data.
    function getRoundData(uint80 _roundId)
        external
        view
        returns (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        )
    {
        (uint256 price, uint256 timestamp, ) = oracle.getRoundData(assetId, _roundId);
        return (
            _roundId,
            int256(price),
            timestamp,
            timestamp,
            _roundId
        );
    }

    /// @notice Simple latest answer getter.
    function latestAnswer() external view returns (int256) {
        (uint256 price, , , ) = oracle.getLatestPrice(assetId);
        return int256(price);
    }

    /// @notice Latest round ID.
    function latestRound() external view returns (uint256) {
        (, , , uint80 round) = oracle.getLatestPrice(assetId);
        return uint256(round);
    }

    /// @notice Latest timestamp.
    function latestTimestamp() external view returns (uint256) {
        (, uint256 timestamp, , ) = oracle.getLatestPrice(assetId);
        return timestamp;
    }

    /// @notice Get answer by round.
    function getAnswer(uint256 _roundId) external view returns (int256) {
        (uint256 price, , ) = oracle.getRoundData(assetId, uint80(_roundId));
        return int256(price);
    }

    /// @notice Get timestamp by round.
    function getTimestamp(uint256 _roundId) external view returns (uint256) {
        (, uint256 timestamp, ) = oracle.getRoundData(assetId, uint80(_roundId));
        return timestamp;
    }
}
