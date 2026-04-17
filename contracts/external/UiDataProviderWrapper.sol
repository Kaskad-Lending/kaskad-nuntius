// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IUiPoolDataProviderV3} from "@aave-v3-origin/src/contracts/helpers/interfaces/IUiPoolDataProviderV3.sol";
import {IPoolAddressesProvider} from "@aave-v3-origin/src/contracts/interfaces/IPoolAddressesProvider.sol";
import {IPool} from "@aave-v3-origin/src/contracts/interfaces/IPool.sol";

/// @title IKaskadPriceOracle — minimal interface for price updates.
interface IKaskadPriceOracleForWrapper {
    function updatePrice(
        bytes32 assetId,
        uint256 price,
        uint256 timestamp,
        uint8   numSources,
        bytes32 sourcesHash,
        bytes calldata signature
    ) external;

    error StalePrice(uint256 provided, uint256 current);
}

/// @title UiDataProviderWrapper
/// @notice Pushes fresh Enclave prices then reads protocol state in a single eth_call.
///
/// Pattern: frontend calls these functions via eth_call (staticcall simulation).
/// Inside, the wrapper pushes signed prices to KaskadPriceOracle (state change
/// that only exists within the simulation), then reads UiPoolDataProvider /
/// Pool with those fresh prices visible.
///
/// All functions revert with the result data to guarantee no on-chain state
/// changes even if accidentally sent as a real transaction.
contract UiDataProviderWrapper {

    IKaskadPriceOracleForWrapper public immutable oracle;
    IUiPoolDataProviderV3 public immutable uiDataProvider;

    struct PriceUpdate {
        bytes32 assetId;
        uint256 price;
        uint256 timestamp;
        uint8   numSources;
        bytes32 sourcesHash;
        bytes   signature;
    }

    /// @dev Reverted with encoded result data.
    error ResultData(bytes data);

    constructor(address _oracle, address _uiDataProvider) {
        oracle = IKaskadPriceOracleForWrapper(_oracle);
        uiDataProvider = IUiPoolDataProviderV3(_uiDataProvider);
    }

    error PriceUpdateFailed(bytes32 assetId, bytes reason);

    /// @dev Push prices to oracle. Skips StalePrice (price already fresh on-chain).
    ///      Reverts with PriceUpdateFailed on real errors (bad sig, etc).
    ///      Frontend distinguishes ResultData (success) from PriceUpdateFailed (error)
    ///      by checking the revert selector.
    function _pushPrices(PriceUpdate[] calldata prices) internal {
        for (uint256 i = 0; i < prices.length; i++) {
            try oracle.updatePrice(
                prices[i].assetId,
                prices[i].price,
                prices[i].timestamp,
                prices[i].numSources,
                prices[i].sourcesHash,
                prices[i].signature
            ) {} catch (bytes memory reason) {
                bytes4 selector = bytes4(reason);
                if (selector == IKaskadPriceOracleForWrapper.StalePrice.selector
                ) {
                    continue;
                }
                revert PriceUpdateFailed(prices[i].assetId, reason);
            }
        }
    }

    /// @notice Get reserves data with fresh prices.
    /// @dev Call via eth_call. Pushes prices, reads data, reverts with result.
    function getReservesData(
        PriceUpdate[] calldata prices,
        IPoolAddressesProvider provider
    ) external {
        _pushPrices(prices);

        (
            IUiPoolDataProviderV3.AggregatedReserveData[] memory reserves,
            IUiPoolDataProviderV3.BaseCurrencyInfo memory baseCurrencyInfo
        ) = uiDataProvider.getReservesData(provider);

        revert ResultData(abi.encode(reserves, baseCurrencyInfo));
    }

    /// @notice Get user reserves data with fresh prices.
    /// @dev Call via eth_call. Pushes prices, reads data, reverts with result.
    function getUserReservesData(
        PriceUpdate[] calldata prices,
        IPoolAddressesProvider provider,
        address user
    ) external {
        _pushPrices(prices);

        (
            IUiPoolDataProviderV3.UserReserveData[] memory userReserves,
            uint8 userEmode
        ) = uiDataProvider.getUserReservesData(provider, user);

        revert ResultData(abi.encode(userReserves, userEmode));
    }

    /// @notice Get user account data with fresh prices.
    /// @dev Call via eth_call. Pushes prices, reads data, reverts with result.
    function getUserAccountData(
        PriceUpdate[] calldata prices,
        IPoolAddressesProvider provider,
        address user
    ) external {
        _pushPrices(prices);

        IPool pool = IPool(provider.getPool());

        (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            uint256 availableBorrowsBase,
            uint256 currentLiquidationThreshold,
            uint256 ltv,
            uint256 healthFactor
        ) = pool.getUserAccountData(user);

        revert ResultData(abi.encode(
            totalCollateralBase,
            totalDebtBase,
            availableBorrowsBase,
            currentLiquidationThreshold,
            ltv,
            healthFactor
        ));
    }
}
