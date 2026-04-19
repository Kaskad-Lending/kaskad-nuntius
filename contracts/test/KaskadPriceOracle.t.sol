// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/KaskadPriceOracle.sol";
import "../src/KaskadAggregatorV3.sol";
import "./mocks/MockVerifiers.sol";

contract KaskadPriceOracleTest is Test {
    KaskadPriceOracle oracle;
    KaskadAggregatorV3 ethAggregator;
    MockAttestationVerifier mockVerifier;

    uint256 internal signerPrivateKey;
    address internal signer;
    address internal admin = address(0xAD31);

    bytes32 internal constant EXPECTED_PCR0 = keccak256("kaskad-oracle:v0.1");
    bytes32 internal constant ETH_USD = keccak256("ETH/USD");
    bytes32 internal constant BTC_USD = keccak256("BTC/USD");

    function setUp() public {
        vm.warp(1710000000);

        signerPrivateKey = 0xA11CE;
        signer = vm.addr(signerPrivateKey);

        mockVerifier = new MockAttestationVerifier(EXPECTED_PCR0, signer);
        oracle = new KaskadPriceOracle(EXPECTED_PCR0, address(mockVerifier), admin);

        oracle.registerEnclave(hex"00");

        bytes32[] memory ids = new bytes32[](2);
        uint8[] memory mins = new uint8[](2);
        ids[0] = ETH_USD; mins[0] = 3;
        ids[1] = BTC_USD; mins[1] = 3;
        _registerAssets(oracle, ids, mins);

        ethAggregator = new KaskadAggregatorV3(address(oracle), ETH_USD, "ETH / USD");
    }

    /// @dev Sort ids ascending and call registerAssets as admin.
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

    // ─── Helpers ─────────────────────────────────────────────────────

    function _signUpdate(
        bytes32 assetId,
        uint256 price,
        uint256 timestamp,
        uint8 numSources,
        bytes32 sourcesHash
    ) internal view returns (bytes memory) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(assetId, price, timestamp, numSources, sourcesHash)
        );
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    function _submitPrice(
        bytes32 assetId,
        uint256 price,
        uint256 timestamp,
        uint8 numSources
    ) internal {
        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(assetId, price, timestamp, numSources, sourcesHash);
        oracle.updatePrice(assetId, price, timestamp, numSources, sourcesHash, sig);
    }

    // ─── Permissionless: No Owner ────────────────────────────────────

    function test_no_owner_functions() public view {
        // Contract has NO owner(), NO setOracleSigner(), NO transferOwnership().
        // Signer was added to the valid-signer set via attestation.
        assertTrue(oracle.validSigner(signer));
        assertEq(oracle.signerCount(), 1);
    }

    function test_validSigner_getter() public view {
        assertTrue(oracle.validSigner(signer));
        assertTrue(oracle.isValidSigner(signer));
        assertFalse(oracle.validSigner(address(0xDEAD)));
    }

    function test_immutable_config() public view {
        assertEq(oracle.expectedPCR0(), EXPECTED_PCR0);
        assertEq(address(oracle.verifier()), address(mockVerifier));
        assertEq(oracle.DECIMALS(), 8);
    }

    // ─── Enclave Registration ────────────────────────────────────────

    function test_registerEnclave_success() public {
        // Deploy fresh oracle
        KaskadPriceOracle fresh = new KaskadPriceOracle(EXPECTED_PCR0, address(mockVerifier), admin);

        // Anyone can register
        vm.prank(address(0xCAFE)); // random caller
        fresh.registerEnclave(hex"deadbeef");

        assertTrue(fresh.validSigner(signer));
        assertEq(fresh.signerCount(), 1);
    }

    function test_registerEnclave_idempotent() public {
        // setUp registered `signer` once. A second call with the same
        // attestation is a no-op: signerCount stays 1, no additional
        // EnclaveRegistered event.
        assertEq(oracle.signerCount(), 1);
        oracle.registerEnclave(hex"00");
        assertEq(oracle.signerCount(), 1);
        assertTrue(oracle.validSigner(signer));
    }

    function test_registerEnclave_revert_invalid_attestation() public {
        FailingAttestationVerifier failVerifier = new FailingAttestationVerifier();
        KaskadPriceOracle oracleWithFailVerifier = new KaskadPriceOracle(
            EXPECTED_PCR0,
            address(failVerifier),
            admin
        );

        vm.expectRevert(KaskadPriceOracle.InvalidAttestation.selector);
        oracleWithFailVerifier.registerEnclave(hex"00");
    }

    function test_registerEnclave_revert_pcr0_mismatch() public {
        WrongPCR0Verifier wrongVerifier = new WrongPCR0Verifier(signer);
        KaskadPriceOracle oracleWithWrongPCR = new KaskadPriceOracle(
            EXPECTED_PCR0,
            address(wrongVerifier),
            admin
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.PCR0Mismatch.selector,
                bytes32(uint256(0xDEAD)),
                EXPECTED_PCR0
            )
        );
        oracleWithWrongPCR.registerEnclave(hex"00");
    }

    function test_registerEnclave_fresh_oracle_adds_signer() public {
        // A fresh oracle wired to a different verifier accepts ITS signer
        // into its own set. Doesn't touch any other oracle's set — each
        // deployment is independent.
        address otherSigner = address(0xBEEF);
        MockAttestationVerifier otherVerifier = new MockAttestationVerifier(EXPECTED_PCR0, otherSigner);
        KaskadPriceOracle o = new KaskadPriceOracle(EXPECTED_PCR0, address(otherVerifier), admin);

        o.registerEnclave(hex"00");
        assertTrue(o.validSigner(otherSigner));
        assertFalse(o.validSigner(signer));
        assertEq(o.signerCount(), 1);
    }

    // ─── Price Updates ───────────────────────────────────────────────

    function test_updatePrice_valid() public {
        uint256 price = 212926000000; // $2129.26
        uint256 ts = 1710000000;
        uint8 sources = 4;
        bytes32 sourcesHash = keccak256("test_sources");

        bytes memory sig = _signUpdate(ETH_USD, price, ts, sources, sourcesHash);

        vm.expectEmit(true, false, false, true);
        emit KaskadPriceOracle.PriceUpdated(ETH_USD, price, ts, sources, 1);

        oracle.updatePrice(ETH_USD, price, ts, sources, sourcesHash, sig);

        (uint256 storedPrice, uint256 storedTs, uint8 storedSources, uint80 roundId) =
            oracle.getLatestPrice(ETH_USD);
        assertEq(storedPrice, price);
        assertEq(storedTs, ts);
        assertEq(storedSources, sources);
        assertEq(roundId, 1);
    }

    function test_updatePrice_increments_roundId() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);
        vm.warp(1710000010);
        _submitPrice(ETH_USD, 213000000000, 1710000010, 5); // +10s
        vm.warp(1710000020);
        _submitPrice(ETH_USD, 213100000000, 1710000020, 3); // +10s

        (, , , uint80 roundId) = oracle.getLatestPrice(ETH_USD);
        assertEq(roundId, 3);
    }

    function test_updatePrice_multiple_assets() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);
        _submitPrice(BTC_USD, 7173690000000, 1710000001, 5);

        (uint256 ethPrice, , , ) = oracle.getLatestPrice(ETH_USD);
        (uint256 btcPrice, , , ) = oracle.getLatestPrice(BTC_USD);

        assertEq(ethPrice, 212926000000);
        assertEq(btcPrice, 7173690000000);
    }

    function test_updatePrice_history() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 3);
        vm.warp(1710000010);
        _submitPrice(ETH_USD, 100100000000, 1710000010, 4); // +0.1%, within circuit breaker

        (uint256 price1, uint256 ts1, ) = oracle.getRoundData(ETH_USD, 1);
        assertEq(price1, 100000000000);
        assertEq(ts1, 1710000000);

        (uint256 price2, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price2, 100100000000);
    }

    // ─── Rejections ──────────────────────────────────────────────────

    function test_updatePrice_reverts_no_enclave() public {
        KaskadPriceOracle unregistered = new KaskadPriceOracle(EXPECTED_PCR0, address(mockVerifier), admin);
        // Don't register enclave

        uint256 ts = block.timestamp;
        bytes32 sourcesHash = keccak256("test");
        bytes memory sig = _signUpdate(ETH_USD, 100, ts, 3, sourcesHash);

        vm.expectRevert(KaskadPriceOracle.NoEnclaveRegistered.selector);
        unregistered.updatePrice(ETH_USD, 100, ts, 3, sourcesHash, sig);
    }

    function test_updatePrice_reverts_invalid_signature() public {
        uint256 wrongKey = 0xBAD;
        uint256 ts = block.timestamp;
        bytes32 sourcesHash = keccak256("test");
        bytes32 messageHash = keccak256(
            abi.encodePacked(ETH_USD, uint256(100), ts, uint8(3), sourcesHash)
        );
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, ethSignedHash);

        vm.expectRevert(KaskadPriceOracle.InvalidSignature.selector);
        oracle.updatePrice(ETH_USD, 100, ts, 3, sourcesHash, abi.encodePacked(r, s, v));
    }

    function test_updatePrice_reverts_stale_timestamp() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);

        vm.warp(1710000010);
        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 212900000000, 1709999999, 4, sourcesHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.StalePrice.selector,
                uint256(1709999999),
                uint256(1710000000)
            )
        );
        oracle.updatePrice(ETH_USD, 212900000000, 1709999999, 4, sourcesHash, sig);
    }

    function test_updatePrice_reverts_short_signature() public {
        uint256 ts = block.timestamp;
        vm.expectRevert();
        oracle.updatePrice(ETH_USD, 100, ts, 3, bytes32(0), hex"aabbcc");
    }

    // ─── Circuit Breaker ─────────────────────────────────────────────

    function test_circuit_breaker_rejects_extreme_price_change() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 4); // $1000

        vm.warp(1710000010);
        // Try to update to $1200 = +20% > 15% limit
        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 120000000000, 1710000010, 4, sourcesHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.PriceChangeExceedsLimit.selector,
                uint256(2000), // 20% = 2000 bps
                uint256(1500)  // max 15%
            )
        );
        oracle.updatePrice(ETH_USD, 120000000000, 1710000010, 4, sourcesHash, sig);
    }

    function test_circuit_breaker_allows_normal_price_change() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 4); // $1000

        vm.warp(1710000010);
        // Update to $1100 = +10% < 15% limit → should pass
        _submitPrice(ETH_USD, 110000000000, 1710000010, 4);

        (uint256 price, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price, 110000000000);
    }

    function test_circuit_breaker_first_update_no_limit() public {
        // First update has no previous price, so no circuit breaker
        _submitPrice(ETH_USD, 999999000000, 1710000000, 4);

        (uint256 price, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price, 999999000000);
    }

    // ─── Rate Limiter ────────────────────────────────────────────────

    function test_rapid_updates_allowed() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 4);

        vm.warp(1710000010);
        // Update after 10 seconds → should pass
        _submitPrice(ETH_USD, 100010000000, 1710000010, 4);

        (uint256 price, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price, 100010000000);
    }

    // ─── AggregatorV3 Wrapper ────────────────────────────────────────

    function test_aggregator_latestRoundData() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);

        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) =
            ethAggregator.latestRoundData();

        assertEq(roundId, 1);
        assertEq(answer, int256(uint256(212926000000)));
        assertEq(startedAt, 1710000000);
        assertEq(updatedAt, 1710000000);
        assertEq(answeredInRound, 1);
    }

    function test_aggregator_latestAnswer() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);
        assertEq(ethAggregator.latestAnswer(), int256(uint256(212926000000)));
    }

    function test_aggregator_decimals() public view {
        assertEq(ethAggregator.decimals(), 8);
    }

    function test_aggregator_description() public view {
        assertEq(ethAggregator.description(), "ETH / USD");
    }

    // ─── Circuit Breaker: Staleness Bypass ─────────────────────────

    function test_circuit_breaker_resume_allows_25pct_with_doubled_quorum() public {
        // After >4 h silence the circuit breaker loosens from 15 % to 30 %,
        // but ONLY if the caller doubles the registered quorum. ETH/USD
        // minSources = 3 → resume requires 6.
        _submitPrice(ETH_USD, 100000000000, 1710000000, 6); // $1000

        vm.warp(1710000000 + 5 hours);
        uint256 ts = block.timestamp;
        _submitPrice(ETH_USD, 125000000000, ts, 6); // +25 % at quorum 6 → accepted.

        (uint256 price, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price, 125000000000);
    }

    function test_circuit_breaker_resume_rejects_40pct_even_with_quorum() public {
        // Even with the doubled quorum, > 30 % change reverts on the cap.
        _submitPrice(ETH_USD, 100000000000, 1710000000, 6);

        vm.warp(1710000000 + 5 hours);
        uint256 ts = block.timestamp;

        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 140000000000, ts, 6, sourcesHash); // +40 %
        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.PriceChangeExceedsLimit.selector,
                uint256(4000),
                uint256(3000)
            )
        );
        oracle.updatePrice(ETH_USD, 140000000000, ts, 6, sourcesHash, sig);
    }

    function test_circuit_breaker_resume_rejects_low_quorum() public {
        // Under-quorum resume reverts even for a sane price step.
        _submitPrice(ETH_USD, 100000000000, 1710000000, 6);

        vm.warp(1710000000 + 5 hours);
        uint256 ts = block.timestamp;
        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 125000000000, ts, 5, sourcesHash);
        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.ResumeRequiresHigherQuorum.selector,
                uint8(5),
                uint8(6)
            )
        );
        oracle.updatePrice(ETH_USD, 125000000000, ts, 5, sourcesHash, sig);
    }

    function test_circuit_breaker_NOT_bypassed_within_staleness() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 4); // $1000

        // Jump 1 hour — within CIRCUIT_BREAKER_STALENESS (4h)
        vm.warp(1710000000 + 1 hours);
        uint256 ts = block.timestamp;

        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 150000000000, ts, 4, sourcesHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.PriceChangeExceedsLimit.selector,
                uint256(5000), // 50%
                uint256(1500)
            )
        );
        oracle.updatePrice(ETH_USD, 150000000000, ts, 4, sourcesHash, sig);
    }

    // ─── Future Timestamp Boundary ──────────────────────────────────

    function test_future_timestamp_at_boundary_allowed() public {
        // Exactly MAX_FUTURE_TIMESTAMP (5 min) in the future — should pass
        uint256 ts = block.timestamp + 5 minutes;
        _submitPrice(ETH_USD, 212926000000, ts, 4);

        (uint256 price, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price, 212926000000);
    }

    function test_future_timestamp_allowed() public {
        // Future timestamps are allowed — enclave uses exchange server time,
        // host cannot manipulate. No Chronos-DoS risk.
        uint256 ts = block.timestamp + 1 hours;
        _submitPrice(ETH_USD, 212926000000, ts, 4);

        (uint256 price, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price, 212926000000);
    }

    // ─── Uninitialized Asset ────────────────────────────────────────

    function test_getLatestPrice_reverts_uninitialized() public {
        bytes32 unknownAsset = keccak256("UNKNOWN/USD");
        vm.expectRevert(
            abi.encodeWithSelector(KaskadPriceOracle.NoPriceData.selector, unknownAsset)
        );
        oracle.getLatestPrice(unknownAsset);
    }

    // ─── Zero Sources ───────────────────────────────────────────────

    function test_updatePrice_reverts_zero_sources() public {
        uint256 ts = block.timestamp;
        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 100, ts, 0, sourcesHash);

        vm.expectRevert(KaskadPriceOracle.InsufficientSources.selector);
        oracle.updatePrice(ETH_USD, 100, ts, 0, sourcesHash, sig);
    }

    // ─── Replay Same Timestamp ──────────────────────────────────────

    function test_updatePrice_reverts_replay_same_timestamp() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 4);

        vm.warp(1710000010);
        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 100010000000, 1710000000, 4, sourcesHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.StalePrice.selector,
                uint256(1710000000),
                uint256(1710000000)
            )
        );
        oracle.updatePrice(ETH_USD, 100010000000, 1710000000, 4, sourcesHash, sig);
    }

    // ─── Circuit Breaker: Price Decrease ─────────────────────────────

    function test_circuit_breaker_rejects_extreme_price_decrease() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 4); // $1000

        vm.warp(1710000010);
        // -20% from $1000 to $800
        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 80000000000, 1710000010, 4, sourcesHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.PriceChangeExceedsLimit.selector,
                uint256(2000), // 20%
                uint256(1500)
            )
        );
        oracle.updatePrice(ETH_USD, 80000000000, 1710000010, 4, sourcesHash, sig);
    }

    // ─── AggregatorV3: getAnswer / getTimestamp ─────────────────────

    function test_aggregator_getAnswer() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);
        assertEq(ethAggregator.getAnswer(1), int256(uint256(212926000000)));
    }

    function test_aggregator_getTimestamp() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);
        assertEq(ethAggregator.getTimestamp(1), 1710000000);
    }

    function test_aggregator_roundId_overflow_reverts() public {
        uint256 overflowId = uint256(type(uint80).max) + 1;
        vm.expectRevert(
            abi.encodeWithSelector(KaskadAggregatorV3.RoundIdOverflow.selector, overflowId)
        );
        ethAggregator.getAnswer(overflowId);
    }

    function test_aggregator_getRoundData() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);
        vm.warp(1710000010);
        _submitPrice(ETH_USD, 213000000000, 1710000010, 5);

        (uint80 roundId, int256 answer, , uint256 updatedAt, ) =
            ethAggregator.getRoundData(2);
        assertEq(roundId, 2);
        assertEq(answer, int256(uint256(213000000000)));
        assertEq(updatedAt, 1710000010);
    }

    // ─── Gas Benchmark ───────────────────────────────────────────────

    function test_gas_updatePrice() public {
        bytes32 sourcesHash = keccak256("test");
        bytes memory sig = _signUpdate(ETH_USD, 212926000000, 1710000000, 4, sourcesHash);

        uint256 gasBefore = gasleft();
        oracle.updatePrice(ETH_USD, 212926000000, 1710000000, 4, sourcesHash, sig);
        uint256 gasUsed = gasBefore - gasleft();

        assertLt(gasUsed, 320_000);
        emit log_named_uint("updatePrice gas (cold)", gasUsed);
    }

    function test_gas_registerEnclave() public {
        KaskadPriceOracle fresh = new KaskadPriceOracle(EXPECTED_PCR0, address(mockVerifier), admin);

        uint256 gasBefore = gasleft();
        fresh.registerEnclave(hex"00");
        uint256 gasUsed = gasBefore - gasleft();

        assertLt(gasUsed, 200_000);
        emit log_named_uint("registerEnclave gas", gasUsed);
    }
}

// ─── E2E: Full Relayer Flow ──────────────────────────────────────────────
// Simulates the complete path: deploy → register enclave → relayer submits
// signed prices for all 5 assets → prices readable via AggregatorV3 wrappers.

contract RelayerE2ETest is Test {
    KaskadPriceOracle oracle;
    MockAttestationVerifier mockVerifier;

    // AggregatorV3 wrappers per asset
    KaskadAggregatorV3 ethAgg;
    KaskadAggregatorV3 btcAgg;
    KaskadAggregatorV3 kasAgg;
    KaskadAggregatorV3 usdcAgg;
    KaskadAggregatorV3 igraAgg;

    uint256 internal signerPk;   // enclave signer key
    address internal signerAddr;

    address internal relayer = address(0xBE1A);  // permissionless gas-payer
    address internal admin = address(0xAD31);

    bytes32 internal constant PCR0 = keccak256("kaskad-oracle:v0.1");

    bytes32 internal constant ETH_USD  = keccak256("ETH/USD");
    bytes32 internal constant BTC_USD  = keccak256("BTC/USD");
    bytes32 internal constant KAS_USD  = keccak256("KAS/USD");
    bytes32 internal constant USDC_USD = keccak256("USDC/USD");
    bytes32 internal constant IGRA_USD = keccak256("IGRA/USD");

    uint256 internal constant T0 = 1710000000;

    function setUp() public {
        vm.warp(T0);

        signerPk = 0xA11CE;
        signerAddr = vm.addr(signerPk);

        mockVerifier = new MockAttestationVerifier(PCR0, signerAddr);
        oracle = new KaskadPriceOracle(PCR0, address(mockVerifier), admin);
        oracle.registerEnclave(hex"00");

        bytes32[] memory ids = new bytes32[](5);
        uint8[] memory mins = new uint8[](5);
        ids[0] = ETH_USD;  mins[0] = 3;
        ids[1] = BTC_USD;  mins[1] = 3;
        ids[2] = KAS_USD;  mins[2] = 3;
        ids[3] = USDC_USD; mins[3] = 2;
        ids[4] = IGRA_USD; mins[4] = 1;
        _registerAssetsOnto(oracle, ids, mins);

        ethAgg  = new KaskadAggregatorV3(address(oracle), ETH_USD,  "ETH / USD");
        btcAgg  = new KaskadAggregatorV3(address(oracle), BTC_USD,  "BTC / USD");
        kasAgg  = new KaskadAggregatorV3(address(oracle), KAS_USD,  "KAS / USD");
        usdcAgg = new KaskadAggregatorV3(address(oracle), USDC_USD, "USDC / USD");
        igraAgg = new KaskadAggregatorV3(address(oracle), IGRA_USD, "IGRA / USD");
    }

    function _registerAssetsOnto(
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

    function _sign(
        bytes32 assetId, uint256 price, uint256 ts, uint8 sources, bytes32 srcHash
    ) internal view returns (bytes memory) {
        bytes32 msgHash = keccak256(abi.encodePacked(assetId, price, ts, sources, srcHash));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, ethHash);
        return abi.encodePacked(r, s, v);
    }

    function _relayPrice(
        bytes32 assetId, uint256 price, uint256 ts, uint8 sources
    ) internal {
        bytes32 srcHash = keccak256(abi.encodePacked("sources_", assetId, ts));
        bytes memory sig = _sign(assetId, price, ts, sources, srcHash);
        vm.prank(relayer);
        oracle.updatePrice(assetId, price, ts, sources, srcHash, sig);
    }

    // ─── E2E: Round 1 — initial prices for all 5 assets ────────────

    function test_e2e_round1_all_assets() public {
        _relayPrice(ETH_USD,   212926000000,  T0,   5); // $2129.26
        _relayPrice(BTC_USD,  7173690000000,  T0+1, 5); // $71736.90
        _relayPrice(KAS_USD,      11200000,   T0+2, 4); // $0.112
        _relayPrice(USDC_USD,   100000000,    T0+3, 3); // $1.00
        _relayPrice(IGRA_USD,    10000000,    T0+4, 3); // $0.10

        // Verify via oracle reads
        (uint256 ethP, , uint8 ethS, uint80 ethR) = oracle.getLatestPrice(ETH_USD);
        assertEq(ethP, 212926000000);
        assertEq(ethS, 5);
        assertEq(ethR, 1);

        (uint256 btcP, , , ) = oracle.getLatestPrice(BTC_USD);
        assertEq(btcP, 7173690000000);

        (uint256 kasP, , , ) = oracle.getLatestPrice(KAS_USD);
        assertEq(kasP, 11200000);

        (uint256 usdcP, , , ) = oracle.getLatestPrice(USDC_USD);
        assertEq(usdcP, 100000000);

        (uint256 igraP, , , ) = oracle.getLatestPrice(IGRA_USD);
        assertEq(igraP, 10000000);

        // Verify via AggregatorV3 wrappers (Chainlink-compatible)
        assertEq(ethAgg.latestAnswer(),  int256(uint256(212926000000)));
        assertEq(btcAgg.latestAnswer(),  int256(uint256(7173690000000)));
        assertEq(kasAgg.latestAnswer(),  int256(uint256(11200000)));
        assertEq(usdcAgg.latestAnswer(), int256(uint256(100000000)));
        assertEq(igraAgg.latestAnswer(), int256(uint256(10000000)));
    }

    // ─── E2E: Round 2 — price updates with deviation ───────────────

    function test_e2e_round2_price_updates() public {
        // Round 1
        _relayPrice(ETH_USD,  212926000000, T0,   5);
        _relayPrice(BTC_USD, 7173690000000, T0+1, 5);

        // Advance 30 seconds
        vm.warp(T0 + 30);

        // Round 2: ETH +1.2%, BTC -0.5% — within circuit breaker
        _relayPrice(ETH_USD,  215481000000, T0+30,  5); // $2154.81
        _relayPrice(BTC_USD, 7137822000000, T0+31, 5); // $71378.22

        // Check round IDs advanced
        (, , , uint80 ethRound) = oracle.getLatestPrice(ETH_USD);
        (, , , uint80 btcRound) = oracle.getLatestPrice(BTC_USD);
        assertEq(ethRound, 2);
        assertEq(btcRound, 2);

        // Check history preserved
        (uint256 ethR1Price, , ) = oracle.getRoundData(ETH_USD, 1);
        assertEq(ethR1Price, 212926000000);

        // AggregatorV3 returns latest
        (, int256 ethLatest, , uint256 ethUpdatedAt, ) = ethAgg.latestRoundData();
        assertEq(ethLatest, int256(uint256(215481000000)));
        assertEq(ethUpdatedAt, T0 + 30);
    }

    // ─── E2E: Relayer stale-skip — same data twice ─────────────────

    function test_e2e_relayer_stale_skip() public {
        _relayPrice(ETH_USD, 212926000000, T0, 5);

        vm.warp(T0 + 30);

        // Relayer reads getLatestPrice, sees timestamp == T0
        (, uint256 onchainTs, , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(onchainTs, T0);

        // Relayer has signed update with same timestamp — should NOT submit
        // (this is what the relayer does in relay.ts: signedTs <= onchainTs → skip)
        // If it DID submit, it would revert:
        bytes32 srcHash = keccak256(abi.encodePacked("sources_", ETH_USD, T0));
        bytes memory sig = _sign(ETH_USD, 212926000000, T0, 5, srcHash);
        vm.prank(relayer);
        vm.expectRevert(
            abi.encodeWithSelector(KaskadPriceOracle.StalePrice.selector, T0, T0)
        );
        oracle.updatePrice(ETH_USD, 212926000000, T0, 5, srcHash, sig);
    }

    // ─── E2E: Circuit breaker protects, then staleness bypass ──────

    function test_e2e_circuit_breaker_then_ramped_resume() public {
        _relayPrice(ETH_USD, 100000000000, T0, 5); // $1000

        // 30s later: flash crash to $700 (-30 %) would exceed the 15 %
        // regular cap and is rejected.
        vm.warp(T0 + 30);
        bytes32 srcHash = keccak256(abi.encodePacked("sources_", ETH_USD, T0 + 30));
        bytes memory sig = _sign(ETH_USD, 70000000000, T0 + 30, 5, srcHash);
        vm.prank(relayer);
        vm.expectRevert();
        oracle.updatePrice(ETH_USD, 70000000000, T0 + 30, 5, srcHash, sig);

        // Price stuck at $1000. 5 hours pass — the resume path opens but
        // requires the registered quorum (3) × RESUME_QUORUM_MULTIPLIER (2)
        // = 6 sources AND a step ≤ 30 %. The first ramp step clamps to
        // $750 (-25 %).
        vm.warp(T0 + 5 hours);
        uint256 ts = block.timestamp;
        _relayPrice(ETH_USD, 75000000000, ts, 6); // -25 %, qu=6

        (uint256 price, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price, 75000000000);
    }

    // ─── E2E: Multiple relayers submit — second one reverts ────────

    function test_e2e_duplicate_relayer_reverts() public {
        address relayer2 = address(0xBEEF);

        // Relayer 1 submits
        _relayPrice(ETH_USD, 212926000000, T0, 5);

        vm.warp(T0 + 10);

        // Relayer 2 has the SAME signed update (same timestamp T0)
        bytes32 srcHash = keccak256(abi.encodePacked("sources_", ETH_USD, T0));
        bytes memory sig = _sign(ETH_USD, 212926000000, T0, 5, srcHash);

        vm.prank(relayer2);
        vm.expectRevert(
            abi.encodeWithSelector(KaskadPriceOracle.StalePrice.selector, T0, T0)
        );
        oracle.updatePrice(ETH_USD, 212926000000, T0, 5, srcHash, sig);
    }

    // ─── E2E: Full 5-round lifecycle ───────────────────────────────

    function test_e2e_five_round_lifecycle() public {
        // Simulate 5 oracle cycles, 30s apart, for ETH
        uint256[5] memory prices = [
            uint256(212926000000),  // $2129.26
            uint256(213200000000),  // $2132.00  +0.13%
            uint256(212500000000),  // $2125.00  -0.33%
            uint256(214000000000),  // $2140.00  +0.71%
            uint256(213800000000)   // $2138.00  -0.09%
        ];

        for (uint256 i = 0; i < 5; i++) {
            uint256 ts = T0 + (i * 30);
            vm.warp(ts);
            _relayPrice(ETH_USD, prices[i], ts, 5);
        }

        // Latest should be round 5
        (uint256 latestPrice, uint256 latestTs, , uint80 latestRound) =
            oracle.getLatestPrice(ETH_USD);
        assertEq(latestPrice, 213800000000);
        assertEq(latestTs, T0 + 120);
        assertEq(latestRound, 5);

        // History fully preserved
        for (uint256 i = 0; i < 5; i++) {
            (uint256 hp, , ) = oracle.getRoundData(ETH_USD, uint80(i + 1));
            assertEq(hp, prices[i]);
        }

        // AggregatorV3 reflects latest
        (, int256 answer, , , ) = ethAgg.latestRoundData();
        assertEq(answer, int256(uint256(213800000000)));
        assertEq(ethAgg.latestRound(), 5);
    }

    // ─── E2E: Enclave re-registration (rotation) ──────────────────

    function test_e2e_fresh_oracle_rejects_foreign_signer() public {
        // A signature from one oracle's signer isn't valid on another
        // oracle with a different (independent) signer set.
        _relayPrice(ETH_USD, 212926000000, T0, 5);

        // Fresh oracle, fresh verifier, fresh enclave key.
        uint256 newPk = 0xBEEF1;
        address newAddr = vm.addr(newPk);
        MockAttestationVerifier newVerifier = new MockAttestationVerifier(PCR0, newAddr);
        KaskadPriceOracle fresh = new KaskadPriceOracle(PCR0, address(newVerifier), admin);
        fresh.registerEnclave(hex"00");
        assertTrue(fresh.validSigner(newAddr));
        assertFalse(fresh.validSigner(signerAddr));
        assertEq(fresh.signerCount(), 1);

        // Admin must (re-)bless the asset quorum on the fresh oracle —
        // otherwise updatePrice hits AssetNotRegistered before signature
        // check fires.
        bytes32[] memory ids = new bytes32[](1);
        uint8[] memory mins = new uint8[](1);
        ids[0] = ETH_USD; mins[0] = 3;
        _registerAssetsOnto(fresh, ids, mins);

        // A signature from the *other* oracle's signer is rejected here.
        bytes32 srcHash = keccak256("test");
        bytes memory oldSig = _sign(ETH_USD, 100, T0, 3, srcHash);
        vm.prank(relayer);
        vm.expectRevert(KaskadPriceOracle.InvalidSignature.selector);
        fresh.updatePrice(ETH_USD, 100, T0, 3, srcHash, oldSig);
    }

    // (the `_registerAssetsOnto` helper above is shared between setUp and
    // this rotation test; no second admin-sig variant is needed now.)
}
