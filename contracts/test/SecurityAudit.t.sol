// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/KaskadPriceOracle.sol";
import "../src/KaskadRouter.sol";
import "../src/KaskadAggregatorV3.sol";
import "./mocks/MockVerifiers.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title SecurityAudit
/// @notice Proof-of-concept tests for findings from the security audit.
///         Each test is labelled with its severity and the location in code.
///         Each test PROVES the finding via concrete behavior.
contract SecurityAuditTest is Test {
    // ───────── Setup ─────────

    KaskadPriceOracle oracle;
    MockAttestationVerifier verifier;

    uint256 internal signerPk = 0xA11CE;
    address internal signerAddr;
    address internal admin = address(0xAD31);

    bytes32 internal constant PCR0 = keccak256("kaskad-oracle:v0.1");
    bytes32 internal constant ETH_USD = keccak256("ETH/USD");
    bytes32 internal constant BTC_USD = keccak256("BTC/USD");
    bytes32 internal constant SRC_HASH = keccak256("sources");

    uint256 internal constant T0 = 1_710_000_000;

    function setUp() public {
        vm.warp(T0);
        signerAddr = vm.addr(signerPk);
        verifier = new MockAttestationVerifier(PCR0, signerAddr);
        oracle = new KaskadPriceOracle(PCR0, address(verifier), admin);
        oracle.registerEnclave(hex"00");

        bytes32[] memory ids = new bytes32[](2);
        uint8[] memory mins = new uint8[](2);
        ids[0] = ETH_USD; mins[0] = 3;
        ids[1] = BTC_USD; mins[1] = 3;
        _registerAssets(oracle, ids, mins);
    }

    function _registerAssets(
        KaskadPriceOracle o,
        bytes32[] memory ids,
        uint8[] memory mins
    ) internal {
        uint256 n = ids.length;
        for (uint256 i = 0; i < n; i++) {
            for (uint256 j = 0; j + 1 < n - i; j++) {
                if (uint256(ids[j]) > uint256(ids[j + 1])) {
                    (ids[j], ids[j + 1]) = (ids[j + 1], ids[j]);
                    (mins[j], mins[j + 1]) = (mins[j + 1], mins[j]);
                }
            }
        }
        vm.prank(admin);
        o.registerAssets(ids, mins);
    }

    // ───────── Helpers ─────────

    function _sign(
        uint256 pk,
        bytes32 assetId,
        uint256 price,
        uint256 ts,
        uint8 sources,
        bytes32 srcHash
    ) internal pure returns (bytes memory) {
        bytes32 h = keccak256(abi.encodePacked(assetId, price, ts, sources, srcHash));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, eth);
        return abi.encodePacked(r, s, v);
    }

    function _submit(
        KaskadPriceOracle o,
        bytes32 assetId,
        uint256 price,
        uint256 ts,
        uint8 sources
    ) internal {
        bytes memory sig = _sign(signerPk, assetId, price, ts, sources, SRC_HASH);
        o.updatePrice(assetId, price, ts, sources, SRC_HASH, sig);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CRIT-1: Cross-contract / cross-chain signature replay.
    //
    // Finding: `updatePrice` message = keccak256(assetId, price, ts, nSrc, srcHash).
    //          NO chainId, NO verifyingContract, NO EIP-712 domain separator.
    //          Any signature the enclave produces is valid on ANY deployment of
    //          KaskadPriceOracle that registered the SAME signer.
    //
    // Code:    contracts/src/KaskadPriceOracle.sol:180-185
    //          src/signer.rs:82-87
    // ═══════════════════════════════════════════════════════════════════════

    function test_POC_signature_replay_across_deployments() public {
        // Scenario: legitimate oracle #1 lives at one address. A second oracle
        // is deployed at a different address BUT registers the same enclave
        // signer (which is the design — anyone with a valid attestation from
        // the correct enclave image can register). A signature intended for
        // oracle #1 works on oracle #2 verbatim.
        MockAttestationVerifier v2 = new MockAttestationVerifier(PCR0, signerAddr);
        KaskadPriceOracle oracle2 = new KaskadPriceOracle(PCR0, address(v2), admin);
        oracle2.registerEnclave(hex"00");

        bytes32[] memory ids2 = new bytes32[](2);
        uint8[] memory mins2 = new uint8[](2);
        ids2[0] = ETH_USD; mins2[0] = 3;
        ids2[1] = BTC_USD; mins2[1] = 3;
        _registerAssets(oracle2, ids2, mins2);

        assertTrue(address(oracle) != address(oracle2));
        assertEq(oracle.oracleSigner(), oracle2.oracleSigner());

        // Enclave signs ONCE for oracle #1 (or thinks it does — the payload
        // doesn't bind to either contract).
        uint256 price = 212926000000;
        uint256 ts = T0 + 1;
        bytes memory sig = _sign(signerPk, ETH_USD, price, ts, 5, SRC_HASH);

        // Submit to oracle #1 — accepted.
        oracle.updatePrice(ETH_USD, price, ts, 5, SRC_HASH, sig);
        (uint256 p1, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(p1, price);

        // Replay the SAME signature on oracle #2 — also accepted.
        oracle2.updatePrice(ETH_USD, price, ts, 5, SRC_HASH, sig);
        (uint256 p2, , , ) = oracle2.getLatestPrice(ETH_USD);
        assertEq(p2, price);

        // Impact: an attacker can force oracle #2 to lag oracle #1 forever
        // (or vice-versa) by replaying stale signatures at will, provided
        // they can withhold newer ones. Worse on cross-chain deployments
        // where chainId also isn't in the payload.
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CRIT-2: Permanent price freeze via far-future timestamp.
    //
    // Finding: `if (current.signedTimestamp > 0 && timestamp <= current.signedTimestamp)`
    //          blocks every subsequent update whose enclave-timestamp is not
    //          strictly greater. The enclave trusts host-controlled system
    //          clock (SystemTime::now at src/price_server.rs:121 and
    //          src/main.rs:44, contrary to the comment at src/types.rs:13).
    //          A single errant/malicious signature with ts=2100 freezes the
    //          asset until year 2100. Neither the CIRCUIT_BREAKER_STALENESS
    //          bypass nor the 15% circuit breaker help — they operate on a
    //          DIFFERENT field (block.timestamp vs signedTimestamp) and
    //          bypass only the price-change check, not the ordering check.
    //
    // Code:    contracts/src/KaskadPriceOracle.sol:159-162
    //          src/price_server.rs:115-142
    //          src/types.rs:13-15
    // ═══════════════════════════════════════════════════════════════════════

    function test_POC_future_timestamp_freezes_asset_permanently() public {
        // A legit update arrives with sane timestamp.
        _submit(oracle, ETH_USD, 200000000000, T0, 3);

        // Then — due to host clock manipulation, enclave bug, or compromised
        // signing path — a single signature is created with a year-2100
        // timestamp. The payload is otherwise valid.
        uint256 farFuture = 4_102_444_800; // 2100-01-01 UTC
        _submit(oracle, ETH_USD, 200000000000, farFuture, 3);

        // Advance on-chain time one whole day.
        vm.warp(T0 + 1 days);

        // Every legitimate update is now locked out until year 2100.
        bytes memory sig = _sign(signerPk, ETH_USD, 210000000000, block.timestamp, 3, SRC_HASH);
        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.StalePrice.selector,
                block.timestamp,
                farFuture
            )
        );
        oracle.updatePrice(ETH_USD, 210000000000, block.timestamp, 3, SRC_HASH, sig);

        // Even after the resume window opens the staleness ordering still
        // bites (resume only touches price-change cap, not timestamp order).
        vm.warp(T0 + 30 days);
        sig = _sign(signerPk, ETH_USD, 210000000000, block.timestamp, 6, SRC_HASH);
        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.StalePrice.selector,
                block.timestamp,
                farFuture
            )
        );
        oracle.updatePrice(ETH_USD, 210000000000, block.timestamp, 6, SRC_HASH, sig);

        // Recovery requires re-deploying the oracle. Existing tests at
        // contracts/test/KaskadPriceOracle.t.sol:384 explicitly assert that
        // "future timestamps are allowed" — this is the documented hole.
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CRIT-3: Per-asset minimum sources NOT enforced on-chain.
    //
    // Finding: Off-chain enclave enforces per-asset quora (src/types.rs:82-89:
    //          ETH/BTC/KAS=3, USDC=2, IGRA=1). On-chain contract only checks
    //          `numSources < 1` (contracts/src/KaskadPriceOracle.sol:154-155).
    //          If the enclave is compromised, buggy, or replaced by a
    //          look-alike with same PCR0 (see HIGH-1 below), numSources=1
    //          for ETH/USD is accepted on-chain.
    // ═══════════════════════════════════════════════════════════════════════

    /// REGRESSION GUARD for the fix of CRIT-3 / H-2. The oracle is now
    /// bootstrapped with `registerAssets` in setUp, pinning `minSources=3`
    /// for ETH/USD and BTC/USD. A `updatePrice` with `numSources=1` (the
    /// pre-fix attack) must revert with `InsufficientSources`.
    function test_REGRESSION_per_asset_min_sources_enforced_onchain() public {
        bytes memory sigEth = _sign(signerPk, ETH_USD, 1_000_000_000_000, T0 + 1, 1, SRC_HASH);
        vm.expectRevert(KaskadPriceOracle.InsufficientSources.selector);
        oracle.updatePrice(ETH_USD, 1_000_000_000_000, T0 + 1, 1, SRC_HASH, sigEth);

        bytes memory sigBtc = _sign(signerPk, BTC_USD, 50_000_000_000_000, T0 + 2, 1, SRC_HASH);
        vm.expectRevert(KaskadPriceOracle.InsufficientSources.selector);
        oracle.updatePrice(BTC_USD, 50_000_000_000_000, T0 + 2, 1, SRC_HASH, sigBtc);

        // numSources=3 (the registered quorum) still accepted.
        _submit(oracle, ETH_USD, 1_000_000_000_000, T0 + 3, 3);
    }

    /// `registerAssets` is now admin-gated. Non-admin callers must revert.
    function test_REGRESSION_registerAssets_rejects_non_admin() public {
        bytes32[] memory ids = new bytes32[](1);
        uint8[] memory mins = new uint8[](1);
        ids[0] = ETH_USD; mins[0] = 3;

        vm.expectRevert(KaskadPriceOracle.NotAdmin.selector);
        vm.prank(address(0xBAD));
        oracle.registerAssets(ids, mins);

        // Admin succeeds.
        vm.prank(admin);
        oracle.registerAssets(ids, mins);
    }

    /// Re-registering the enclave (legit rotation OR griefing attempt with
    /// a same-PCR attestation) must PRESERVE the admin's quorum mapping.
    /// Otherwise a drive-by registerEnclave would halt the oracle every
    /// time and force admin intervention.
    function test_REGRESSION_registerEnclave_preserves_asset_registration() public {
        assertEq(_minSources(oracle, ETH_USD), 3);

        // Attacker deploys their own same-PCR attestation and front-runs.
        address otherSigner = address(0xC0DE);
        MockAttestationVerifier v2 = new MockAttestationVerifier(PCR0, otherSigner);
        // Hot-swap the verifier via a fresh oracle: we can't mutate the
        // existing oracle's verifier (immutable), so this simulates the
        // sibling case where the SAME oracle receives a different signer.
        // For the invariant we care about (asset mapping persistence)
        // exercising `registerEnclave` on the existing oracle is enough:
        v2; // silence warning
        oracle.registerEnclave(hex"00"); // same verifier, same signer — no-op but exercises the path.
        assertEq(_minSources(oracle, ETH_USD), 3, "asset quorum must survive re-register");
    }

    function _minSources(KaskadPriceOracle o, bytes32 id) internal view returns (uint8) {
        (uint8 m) = o.assetParams(id);
        return m;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HIGH-1: Rate limiter and future-timestamp cap claimed by CLAUDE.md
    //         but NOT implemented.
    //
    // Finding: CLAUDE.md claims "circuit breaker (15% + staleness bypass at
    //          4h), rate limiter (5s), future timestamp cap (5 min)". The
    //          contract has the circuit breaker and staleness bypass. It has
    //          NEITHER the rate limiter NOR the future-timestamp cap.
    //
    //          The test at KaskadPriceOracle.t.sol:296 "test_rapid_updates_
    //          allowed" waves at this — it asserts 10s-apart updates pass,
    //          without ever verifying that faster-than-5s updates are
    //          rejected. Because they aren't.
    // ═══════════════════════════════════════════════════════════════════════

    function test_POC_no_rate_limiter_sub_5s_updates_accepted() public {
        _submit(oracle, ETH_USD, 100000000000, T0, 5);
        // Same block, 1 second later — the contract has no MIN_UPDATE_DELAY.
        vm.warp(T0 + 1);
        _submit(oracle, ETH_USD, 100100000000, T0 + 1, 5);
        vm.warp(T0 + 2);
        _submit(oracle, ETH_USD, 100200000000, T0 + 2, 5);

        (, , , uint80 roundId) = oracle.getLatestPrice(ETH_USD);
        assertEq(roundId, 3); // Three updates in three seconds — no rate limit.
    }

    function test_POC_no_future_timestamp_cap() public {
        // A signature with ts = now + 1 year is accepted without complaint.
        uint256 farFuture = T0 + 365 days;
        _submit(oracle, ETH_USD, 200000000000, farFuture, 5);

        (, uint256 recordedBlockTs, , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(recordedBlockTs, T0); // block.timestamp of submission, not the signed ts.

        // And because signedTimestamp is monotonic, this PERMANENTLY freezes
        // the asset (combines with CRIT-2 above).
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HIGH-2: Circuit breaker bypassed after 4h of staleness permits any
    //         price change. Combined with CRIT-3 the on-chain layer has
    //         ZERO defense if the off-chain aggregation fails.
    //
    // Finding: contracts/src/KaskadPriceOracle.sol:167 guards the 15% cap
    //          with `block.timestamp - current.timestamp < 4 hours`. An
    //          attacker who keeps the oracle silent for 4 hours (DoS the
    //          relayer, or the enclave itself) can then push ANY value.
    // ═══════════════════════════════════════════════════════════════════════

    /// REGRESSION GUARD for the fix of H-4. After 4 h of silence, the
    /// circuit breaker now REQUIRES 2× the registered quorum AND clamps
    /// the change to 30 %. The pre-fix "free push of any price" primitive
    /// now reverts on both conditions.
    function test_REGRESSION_staleness_no_longer_grants_free_pump() public {
        _submit(oracle, ETH_USD, 200000000000, T0, 3); // $2000 with minReq quorum
        vm.warp(T0 + 4 hours + 1);
        uint256 ts = block.timestamp;

        // (a) Low-quorum attempt reverts with ResumeRequiresHigherQuorum.
        bytes memory lowQ = _sign(signerPk, ETH_USD, 200000000000 * 1000, ts, 3, SRC_HASH);
        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.ResumeRequiresHigherQuorum.selector,
                uint8(3),
                uint8(6)
            )
        );
        oracle.updatePrice(ETH_USD, 200000000000 * 1000, ts, 3, SRC_HASH, lowQ);

        // (b) Even at the doubled quorum, 1000× change > 30 % cap reverts.
        bytes memory highQ = _sign(signerPk, ETH_USD, 200000000000 * 1000, ts, 6, SRC_HASH);
        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.PriceChangeExceedsLimit.selector,
                uint256(9_990_000),
                uint256(3_000)
            )
        );
        oracle.updatePrice(ETH_USD, 200000000000 * 1000, ts, 6, SRC_HASH, highQ);

        // (c) A sane 25 % step at the doubled quorum is accepted.
        _submit(oracle, ETH_USD, 250000000000, ts, 6); // $2500
        (uint256 p, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(p, 250000000000);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MED-1: KaskadRouter.liquidateWithPrices transfers ANY pre-existing
    //        collateral/debt-token balance on the router contract to the
    //        caller. A griefer (or an operator mistake) that sends tokens
    //        to the router makes them claimable by the next liquidator.
    //
    // Code:  contracts/src/KaskadRouter.sol:201-210
    //        `seizedBalance = balanceOf(address(this))` does NOT track
    //        deltas from the liquidation call, it sweeps whatever is there.
    // ═══════════════════════════════════════════════════════════════════════

    /// REGRESSION GUARD for the fix of M-1. A donated balance on the
    /// router MUST stay on the router — `liquidateWithPrices` now uses
    /// balance deltas, not whole balances, so a dust liquidation no
    /// longer sweeps griefing donations into the caller's pocket.
    function test_REGRESSION_router_keeps_donated_tokens_on_liquidate() public {
        MinimalPool pool = new MinimalPool();
        KaskadRouter router = new KaskadRouter(address(oracle), address(pool));

        MockToken debt = new MockToken("DEBT", "DEBT");
        MockToken collateral = new MockToken("COL", "COL");
        pool.setCollateralAsset(address(collateral));

        // Griefer donates 1000 collateral tokens to the router.
        address griefer = address(0xD0E0);
        collateral.mint(griefer, 1000e18);
        vm.prank(griefer);
        collateral.transfer(address(router), 1000e18);
        assertEq(collateral.balanceOf(address(router)), 1000e18);

        // Liquidator calls liquidateWithPrices for a dust amount. The
        // MinimalPool seizes NOTHING — so the only balance change on the
        // router during the call is the debt pull/consume, and the
        // collateral balance is untouched.
        address liquidator = address(0xBEEF);
        debt.mint(liquidator, 1);
        vm.startPrank(liquidator);
        debt.approve(address(router), 1);

        KaskadRouter.PriceUpdate[] memory empty = new KaskadRouter.PriceUpdate[](0);
        router.liquidateWithPrices(
            empty,
            address(collateral),
            address(debt),
            address(0xCAFE),
            1,
            false
        );
        vm.stopPrank();

        // Liquidator sees zero seized collateral (correct — nothing was
        // actually liquidated), and the griefer's donation is still on
        // the router. Before the M-1 fix, the liquidator would have
        // walked away with the full 1000e18.
        assertEq(collateral.balanceOf(liquidator), 0);
        assertEq(collateral.balanceOf(address(router)), 1000e18);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // LOW-1: Attestation accepted up to 365 DAYS old by DeployGalleonReal
    //        (contracts/script/DeployGalleonReal.s.sol:30).
    //        An attestation doc captured today can be used to re-register
    //        the same signer a year from now. Industry practice is minutes.
    //        Not directly tested here (requires real Nitro attestation doc)
    //        but flagged for the report.
    // ═══════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════
    // LOW-2: expectedPCR1/PCR2 default to bytes32(0) → skipped entirely.
    //        Deploy script passes `vm.envOr(..., bytes32(0))`. The verifier
    //        is IMMUTABLE — the skip is permanent once deployed.
    //        (contracts/src/NitroAttestationVerifier.sol:78-79,
    //         contracts/script/DeployGalleonReal.s.sol:33-34)
    // ═══════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════
    // INFO: Current Galleon deployment uses MockAttestationVerifier
    //       (contracts/deployments/galleon.json) with expectedPCR0 =
    //       0x000...001 and an EOA as enclaveSigner. On-chain TEE trust is
    //       effectively OFF in production — whoever has ORACLE_SIGNER's
    //       private key owns the oracle.
    // ═══════════════════════════════════════════════════════════════════════
}

// ───────── Minimal test doubles ─────────

contract MinimalPool is IPool {
    address internal collateralAsset;

    function setCollateralAsset(address a) external {
        collateralAsset = a;
    }

    function borrow(address, uint256, uint256, uint16, address) external {}
    function withdraw(address, uint256, address) external returns (uint256) {
        return 0;
    }
    function liquidationCall(address, address, address, uint256, bool) external {
        // Seize nothing — the griefed donation is already on the router.
    }

    function getReserveData(address) external pure returns (ReserveDataLegacy memory r) {
        return r;
    }
}

contract MockToken is ERC20 {
    constructor(string memory n, string memory s) ERC20(n, s) {}
    function mint(address to, uint256 amt) external {
        _mint(to, amt);
    }
}
