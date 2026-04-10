// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./KaskadPriceOracle.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title IPool — minimal Aave V3 Pool interface for KaskadRouter.
interface IPool {
    function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) external;
    function withdraw(address asset, uint256 amount, address to) external returns (uint256);
    function liquidationCall(address collateralAsset, address debtAsset, address user, uint256 debtToCover, bool receiveAToken) external;
}

/// @title KaskadRouter
/// @notice Atomic price-update + Aave action in one TX.
///
/// User flow (one-time setup):
///   1. debtToken.approveDelegation(router, type(uint256).max)  — for borrow
///   2. aToken.approve(router, type(uint256).max)               — for withdraw
///
/// User flow (every action):
///   1. Frontend fetches signed prices from enclave pull API
///   2. Frontend calls router.borrowWithPrices(prices, asset, amount, rateMode)
///   3. Router pushes fresh prices → Aave reads them in same TX → executes action
///
/// Security invariant: onBehalfOf is ALWAYS msg.sender. Router cannot
/// act on behalf of anyone other than the caller.
contract KaskadRouter is ReentrancyGuard {
    using SafeERC20 for IERC20;

    KaskadPriceOracle public immutable oracle;
    IPool public immutable pool;

    /// @notice Max age (seconds) for a price payload submitted by a user.
    ///         Prevents cherry-picking stale signatures.
    uint256 public constant MAX_PRICE_AGE = 60;

    struct PriceUpdate {
        bytes32 assetId;
        uint256 price;
        uint256 timestamp;
        uint8   numSources;
        bytes32 sourcesHash;
        bytes   signature;
    }

    error PriceTooOld(uint256 age, uint256 maxAge);
    error PriceUpdateFailed(bytes32 assetId);

    constructor(address _oracle, address _pool) {
        oracle = KaskadPriceOracle(_oracle);
        pool = IPool(_pool);
    }

    // ─── Internal: push prices ──────────────────────────────────────

    /// @dev Validates freshness, then pushes each price to the oracle.
    ///      Only skips StalePrice (price already fresh on-chain).
    ///      Reverts on all other errors (circuit breaker, invalid sig, etc).
    function _pushPrices(PriceUpdate[] calldata prices) internal {
        for (uint256 i = 0; i < prices.length; i++) {
            uint256 age = block.timestamp - prices[i].timestamp;
            if (age > MAX_PRICE_AGE) revert PriceTooOld(age, MAX_PRICE_AGE);

            try oracle.updatePrice(
                prices[i].assetId,
                prices[i].price,
                prices[i].timestamp,
                prices[i].numSources,
                prices[i].sourcesHash,
                prices[i].signature
            ) {} catch (bytes memory reason) {
                // Only skip errors that mean "price is already fresh on-chain"
                bytes4 selector = bytes4(reason);
                if (selector == KaskadPriceOracle.StalePrice.selector) {
                    // Safe: on-chain price is already ahead of this update.
                    continue;
                }
                // Everything else is unsafe to skip (circuit breaker, bad sig, etc)
                revert PriceUpdateFailed(prices[i].assetId);
            }
        }
    }

    // ─── Borrow ─────────────────────────────────────────────────────
    // Requires: debtToken.approveDelegation(router, amount) — one-time
    // Aave V3 sends borrowed tokens directly to onBehalfOf (= msg.sender).

    function borrowWithPrices(
        PriceUpdate[] calldata prices,
        address asset,
        uint256 amount,
        uint256 interestRateMode
    ) external nonReentrant {
        _pushPrices(prices);
        pool.borrow(asset, amount, interestRateMode, 0, msg.sender);
    }

    // ─── Withdraw ───────────────────────────────────────────────────
    // Requires: aToken.approve(router, amount) — one-time
    // Router pulls aTokens, Pool burns them and sends underlying to user.

    function withdrawWithPrices(
        PriceUpdate[] calldata prices,
        address asset,
        address aToken,
        uint256 amount
    ) external nonReentrant {
        _pushPrices(prices);

        // Pull aTokens from user → Router
        uint256 pullAmount = amount == type(uint256).max
            ? IERC20(aToken).balanceOf(msg.sender)
            : amount;
        IERC20(aToken).safeTransferFrom(msg.sender, address(this), pullAmount);

        // Withdraw underlying from Pool → user
        pool.withdraw(asset, pullAmount, msg.sender);
    }

    // ─── Liquidation ────────────────────────────────────────────────
    // Liquidator approves debtAsset to Router.
    // Pool sends seized collateral to msg.sender=Router → forwarded to liquidator.

    function liquidateWithPrices(
        PriceUpdate[] calldata prices,
        address collateralAsset,
        address debtAsset,
        address user,
        uint256 debtToCover,
        bool receiveAToken
    ) external nonReentrant {
        _pushPrices(prices);

        // Pull debt tokens from liquidator
        IERC20(debtAsset).safeTransferFrom(msg.sender, address(this), debtToCover);
        IERC20(debtAsset).forceApprove(address(pool), debtToCover);

        // Execute liquidation
        pool.liquidationCall(collateralAsset, debtAsset, user, debtToCover, receiveAToken);

        // Forward seized collateral (or aToken) to liquidator
        address seizedAsset = receiveAToken ? collateralAsset : collateralAsset;
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
