// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title IKaskadPriceOracle — minimal interface for price updates.
interface IKaskadPriceOracle {
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

/// @title IPool — minimal Aave V3 Pool interface for KaskadRouter.
interface IPool {
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
    function liquidationCall(address collateralAsset, address debtAsset, address user, uint256 debtToCover, bool receiveAToken) external;

    struct ReserveDataLegacy {
        uint256 configuration;
        uint128 liquidityIndex;
        uint128 currentLiquidityRate;
        uint128 variableBorrowIndex;
        uint128 currentVariableBorrowRate;
        uint128 currentStableBorrowRate;
        uint40  lastUpdateTimestamp;
        uint16  id;
        address aTokenAddress;
        address stableDebtTokenAddress;
        address variableDebtTokenAddress;
        address interestRateStrategyAddress;
        uint128 accruedToTreasury;
        uint128 unbacked;
        uint128 isolationModeTotalDebt;
    }
    function getReserveData(address asset) external view returns (ReserveDataLegacy memory);
}

/// @title KaskadRouter
/// @notice Atomic price-update + Aave action in one TX.
///         Stores msg.sender in transient storage so KaskadStalenessChecker
///         can verify price freshness only for the caller's assets.
///
/// User flow (one-time setup):
///   1. debtToken.approveDelegation(router, type(uint256).max)  — for borrow
///   2. aToken.approve(router, type(uint256).max)               — for withdraw
///
/// Security invariant: onBehalfOf is ALWAYS msg.sender. Router cannot
/// act on behalf of anyone other than the caller.
contract KaskadRouter is ReentrancyGuard {
    using SafeERC20 for IERC20;

    IKaskadPriceOracle public immutable oracle;
    IPool public immutable pool;

    /// @notice Transient storage slot for the current caller address.
    ///         Used by KaskadStalenessChecker to identify which user's assets to check.
    bytes32 private constant SENDER_SLOT = keccak256("KaskadRouter.sender");

    struct PriceUpdate {
        bytes32 assetId;
        uint256 price;
        uint256 timestamp;
        uint8   numSources;
        bytes32 sourcesHash;
        bytes   signature;
    }

    error PriceUpdateFailed(bytes32 assetId);

    constructor(address _oracle, address _pool) {
        oracle = IKaskadPriceOracle(_oracle);
        pool = IPool(_pool);
    }

    // ─── Transient storage: caller tracking ────────────────────────────

    /// @notice Returns the address stored in transient storage for the current TX.
    ///         Returns address(0) if called outside of a Router-initiated TX.
    function sender() external view returns (address s) {
        bytes32 slot = SENDER_SLOT;
        assembly {
            s := tload(slot)
        }
    }

    // ─── Internal: push prices ──────────────────────────────────────

    /// @dev Pushes each price to the oracle.
    ///      Only skips StalePrice and UpdateTooFrequent (price already fresh on-chain).
    ///      Reverts on all other errors (circuit breaker, invalid sig, etc).
    ///      Freshness validation is delegated to the oracle contract itself.
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
                // Only skip StalePrice (price is already fresh on-chain)
                bytes4 selector = bytes4(reason);
                if (selector == IKaskadPriceOracle.StalePrice.selector) {
                    // Safe: on-chain price is already at or ahead of this update.
                    continue;
                }
                // Everything else is unsafe to skip (circuit breaker, bad sig, etc)
                revert PriceUpdateFailed(prices[i].assetId);
            }
        }
    }

    /// @dev Sets transient sender, executes action, clears transient sender.
    modifier withSender() {
        bytes32 slot = SENDER_SLOT;
        assembly {
            tstore(slot, caller())
        }
        _;
        // Transient storage auto-clears at end of TX, but we clear explicitly
        // for safety in case of complex call chains within the same TX.
        assembly {
            tstore(slot, 0)
        }
    }

    // ─── Borrow ─────────────────────────────────────────────────────
    // Requires: debtToken.approveDelegation(router, amount) — one-time
    // Aave V3 mints debtToken to onBehalfOf but sends underlying to msg.sender
    // (the caller of pool.borrow = this Router). We forward it to the user.

    function borrowWithPrices(
        PriceUpdate[] calldata prices,
        address asset,
        uint256 amount,
        uint256 interestRateMode
    ) external nonReentrant withSender {
        _pushPrices(prices);
        pool.borrow(asset, amount, interestRateMode, 0, msg.sender);
        IERC20(asset).safeTransfer(msg.sender, amount);
    }

    // ─── Withdraw ───────────────────────────────────────────────────
    // Requires: aToken.approve(router, amount) — one-time
    // Router pulls aTokens, Pool burns them and sends underlying to user.

    function withdrawWithPrices(
        PriceUpdate[] calldata prices,
        address asset,
        address aToken,
        uint256 amount
    ) external nonReentrant withSender {
        _pushPrices(prices);

        // Pull aTokens from user -> Router
        uint256 pullAmount = amount == type(uint256).max
            ? IERC20(aToken).balanceOf(msg.sender)
            : amount;
        IERC20(aToken).safeTransferFrom(msg.sender, address(this), pullAmount);

        // Withdraw underlying from Pool -> user
        pool.withdraw(asset, pullAmount, msg.sender);
    }

    // ─── Liquidation ────────────────────────────────────────────────
    // Liquidator approves debtAsset to Router.
    // Pool sends seized collateral to msg.sender=Router -> forwarded to liquidator.

    function liquidateWithPrices(
        PriceUpdate[] calldata prices,
        address collateralAsset,
        address debtAsset,
        address user,
        uint256 debtToCover,
        bool receiveAToken
    ) external nonReentrant withSender {
        _pushPrices(prices);

        // Pull debt tokens from liquidator
        IERC20(debtAsset).safeTransferFrom(msg.sender, address(this), debtToCover);
        IERC20(debtAsset).forceApprove(address(pool), debtToCover);

        // Execute liquidation
        pool.liquidationCall(collateralAsset, debtAsset, user, debtToCover, receiveAToken);

        // Forward seized collateral (or aToken) to liquidator
        address seizedAsset = receiveAToken
            ? pool.getReserveData(collateralAsset).aTokenAddress
            : collateralAsset;
        uint256 seizedBalance = IERC20(seizedAsset).balanceOf(address(this));
        if (seizedBalance > 0) {
            IERC20(seizedAsset).safeTransfer(msg.sender, seizedBalance);
        }

        // Refund leftover debt tokens (partial liquidation due to close factor)
        uint256 debtLeftover = IERC20(debtAsset).balanceOf(address(this));
        if (debtLeftover > 0) {
            IERC20(debtAsset).safeTransfer(msg.sender, debtLeftover);
        }
    }
}
