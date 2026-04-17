// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPriceOracleSentinel} from "@aave-v3-origin/src/contracts/interfaces/IPriceOracleSentinel.sol";
import {IPoolAddressesProvider} from "@aave-v3-origin/src/contracts/interfaces/IPoolAddressesProvider.sol";
import {IACLManager} from "@aave-v3-origin/src/contracts/interfaces/IACLManager.sol";
import {AggregatorInterface} from "@aave-v3-origin/src/contracts/dependencies/chainlink/AggregatorInterface.sol";
import {IAaveOracle} from "@aave-v3-origin/src/contracts/interfaces/IAaveOracle.sol";
import {IPool} from "@aave-v3-origin/src/contracts/interfaces/IPool.sol";
import {DataTypes} from "@aave-v3-origin/src/contracts/protocol/libraries/types/DataTypes.sol";

/// @title IKaskadRouter — minimal interface for reading transient sender.
interface IKaskadRouter {
    function sender() external view returns (address);
}

/// @title KaskadStalenessChecker
/// @notice Implements IPriceOracleSentinel to enforce per-asset price freshness.
///
/// Two modes depending on how the protocol is accessed:
///   1. Via KaskadRouter: transient storage contains msg.sender.
///      Check freshness only for that user's assets (gas-efficient).
///   2. Direct Pool call: transient storage is empty (address(0)).
///      Check freshness for ALL protocol assets (more expensive, fair penalty).
///
/// If any relevant aggregator's price is stale (updatedAt + maxStaleness < block.timestamp),
/// borrow and liquidation are blocked. Supply, withdraw, and repay are unaffected
/// (they don't call sentinel).
contract KaskadStalenessChecker is IPriceOracleSentinel {

    error CallerNotPoolAdmin();
    error CallerNotRiskOrPoolAdmin();
    error MaxStalenessExceeded(uint256 requested, uint256 maximum);

    /// @notice Absolute upper bound for maxStaleness (4 hours).
    uint256 public constant MAX_STALENESS_CAP = 4 hours;

    IPoolAddressesProvider public immutable override ADDRESSES_PROVIDER;
    IKaskadRouter public immutable router;

    /// @notice Maximum allowed price age in seconds.
    uint256 public maxStaleness;

    modifier onlyPoolAdmin() {
        IACLManager aclManager = IACLManager(ADDRESSES_PROVIDER.getACLManager());
        if (!aclManager.isPoolAdmin(msg.sender)) revert CallerNotPoolAdmin();
        _;
    }

    modifier onlyRiskOrPoolAdmins() {
        IACLManager aclManager = IACLManager(ADDRESSES_PROVIDER.getACLManager());
        if (!aclManager.isRiskAdmin(msg.sender) && !aclManager.isPoolAdmin(msg.sender)) {
            revert CallerNotRiskOrPoolAdmin();
        }
        _;
    }

    constructor(
        IPoolAddressesProvider provider,
        address _router,
        uint256 _maxStaleness
    ) {
        if (_maxStaleness > MAX_STALENESS_CAP) revert MaxStalenessExceeded(_maxStaleness, MAX_STALENESS_CAP);
        ADDRESSES_PROVIDER = provider;
        router = IKaskadRouter(_router);
        maxStaleness = _maxStaleness;
    }

    /// @inheritdoc IPriceOracleSentinel
    function isBorrowAllowed() external view override returns (bool) {
        return _checkFreshness();
    }

    /// @inheritdoc IPriceOracleSentinel
    function isLiquidationAllowed() external view override returns (bool) {
        return _checkFreshness();
    }

    /// @dev Core freshness check.
    ///      If router.sender() != address(0) → check only that user's assets.
    ///      If router.sender() == address(0) → check all protocol assets.
    function _checkFreshness() internal view returns (bool) {
        address user = router.sender();
        IPool pool = IPool(ADDRESSES_PROVIDER.getPool());
        IAaveOracle aaveOracle = IAaveOracle(ADDRESSES_PROVIDER.getPriceOracle());

        if (user != address(0)) {
            return _checkUserAssets(user, pool, aaveOracle);
        } else {
            return _checkAllAssets(pool, aaveOracle);
        }
    }

    /// @dev Check freshness of aggregators for assets the user is supplying or borrowing.
    function _checkUserAssets(
        address user,
        IPool pool,
        IAaveOracle aaveOracle
    ) internal view returns (bool) {
        DataTypes.UserConfigurationMap memory userConfig = pool.getUserConfiguration(user);
        uint256 reservesCount = pool.getReservesCount();

        for (uint256 i = 0; i < reservesCount; i++) {
            // Each reserve uses 2 bits in the bitmap: bit 2i = borrowing, bit 2i+1 = collateral
            if ((userConfig.data >> (i << 1)) & 3 == 0) continue;

            address asset = pool.getReserveAddressById(uint16(i));
            if (asset == address(0)) continue;

            if (!_isAssetFresh(asset, aaveOracle)) return false;
        }
        return true;
    }

    /// @dev Check freshness of ALL protocol asset aggregators.
    function _checkAllAssets(
        IPool pool,
        IAaveOracle aaveOracle
    ) internal view returns (bool) {
        address[] memory reserves = pool.getReservesList();

        for (uint256 i = 0; i < reserves.length; i++) {
            if (!_isAssetFresh(reserves[i], aaveOracle)) return false;
        }
        return true;
    }

    /// @dev Check if a single asset's aggregator price is fresh.
    function _isAssetFresh(address asset, IAaveOracle aaveOracle) internal view returns (bool) {
        address source = aaveOracle.getSourceOfAsset(asset);
        if (source == address(0)) return true; // no aggregator = base currency or fallback

        try AggregatorInterface(source).latestRoundData() returns (
            uint80, int256, uint256, uint256 updatedAt, uint80
        ) {
            return block.timestamp <= updatedAt + maxStaleness;
        } catch {
            // If aggregator reverts (e.g. no price data), treat as stale
            return false;
        }
    }

    // ─── IPriceOracleSentinel: sequencer oracle interface (not used) ────

    /// @inheritdoc IPriceOracleSentinel
    function setSequencerOracle(address) external onlyPoolAdmin {
        // No-op: we don't use a sequencer oracle.
        // Interface requires this method.
    }

    /// @inheritdoc IPriceOracleSentinel
    function setGracePeriod(uint256 newGracePeriod) external onlyRiskOrPoolAdmins {
        if (newGracePeriod > MAX_STALENESS_CAP) revert MaxStalenessExceeded(newGracePeriod, MAX_STALENESS_CAP);
        maxStaleness = newGracePeriod;
        emit GracePeriodUpdated(newGracePeriod);
    }

    /// @inheritdoc IPriceOracleSentinel
    function getSequencerOracle() external view returns (address) {
        return address(0);
    }

    /// @inheritdoc IPriceOracleSentinel
    function getGracePeriod() external view returns (uint256) {
        return maxStaleness;
    }
}
