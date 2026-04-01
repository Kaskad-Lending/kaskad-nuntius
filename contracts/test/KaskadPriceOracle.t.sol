// SPDX-License-Identifier: MIT
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

    bytes32 internal constant EXPECTED_PCR0 = keccak256("kaskad-oracle:v0.1");
    bytes32 internal constant ETH_USD = keccak256("ETH/USD");
    bytes32 internal constant BTC_USD = keccak256("BTC/USD");

    function setUp() public {
        // Warp block.timestamp to be in range of test timestamps (~1710000000)
        vm.warp(1710000000);

        signerPrivateKey = 0xA11CE;
        signer = vm.addr(signerPrivateKey);

        // Deploy mock verifier that returns our expected PCR0 and signer
        mockVerifier = new MockAttestationVerifier(EXPECTED_PCR0, signer);

        // Deploy oracle with expected PCR0 and mock verifier
        oracle = new KaskadPriceOracle(EXPECTED_PCR0, address(mockVerifier));

        // Register enclave (via mock attestation)
        oracle.registerEnclave(hex"00"); // any bytes, mock verifier accepts all

        // Deploy AggregatorV3 wrapper
        ethAggregator = new KaskadAggregatorV3(
            address(oracle),
            ETH_USD,
            "ETH / USD"
        );
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
        // Contract has NO owner(), NO setOracleSigner(), NO transferOwnership()
        // Verify enclave was registered via attestation
        (address enclSigner, , , bool active) = oracle.enclave();
        assertEq(enclSigner, signer);
        assertTrue(active);
    }

    function test_oracleSigner_getter() public view {
        assertEq(oracle.oracleSigner(), signer);
    }

    function test_immutable_config() public view {
        assertEq(oracle.expectedPCR0(), EXPECTED_PCR0);
        assertEq(address(oracle.verifier()), address(mockVerifier));
        assertEq(oracle.DECIMALS(), 8);
    }

    // ─── Enclave Registration ────────────────────────────────────────

    function test_registerEnclave_success() public {
        // Deploy fresh oracle
        KaskadPriceOracle fresh = new KaskadPriceOracle(EXPECTED_PCR0, address(mockVerifier));

        // Anyone can register
        vm.prank(address(0xCAFE)); // random caller
        fresh.registerEnclave(hex"deadbeef");

        assertEq(fresh.oracleSigner(), signer);
    }

    function test_registerEnclave_revert_invalid_attestation() public {
        FailingAttestationVerifier failVerifier = new FailingAttestationVerifier();
        KaskadPriceOracle oracleWithFailVerifier = new KaskadPriceOracle(
            EXPECTED_PCR0,
            address(failVerifier)
        );

        vm.expectRevert(KaskadPriceOracle.InvalidAttestation.selector);
        oracleWithFailVerifier.registerEnclave(hex"00");
    }

    function test_registerEnclave_revert_pcr0_mismatch() public {
        WrongPCR0Verifier wrongVerifier = new WrongPCR0Verifier(signer);
        KaskadPriceOracle oracleWithWrongPCR = new KaskadPriceOracle(
            EXPECTED_PCR0,
            address(wrongVerifier)
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

    function test_registerEnclave_replaces_old_signer() public {
        // A new valid enclave can replace the old one (e.g. after restart)
        address newSigner = address(0xBEEF);
        MockAttestationVerifier newVerifier = new MockAttestationVerifier(EXPECTED_PCR0, newSigner);
        KaskadPriceOracle o = new KaskadPriceOracle(EXPECTED_PCR0, address(newVerifier));

        o.registerEnclave(hex"00");
        assertEq(o.oracleSigner(), newSigner);
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
        KaskadPriceOracle unregistered = new KaskadPriceOracle(EXPECTED_PCR0, address(mockVerifier));
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

    function test_rate_limiter_rejects_too_fast() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 4);

        vm.warp(1710000002);
        // Try to update 2 seconds later (< 5s minimum)
        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 100010000000, 1710000002, 4, sourcesHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.UpdateTooFrequent.selector,
                uint256(2), // elapsed
                uint256(5)  // min delay
            )
        );
        oracle.updatePrice(ETH_USD, 100010000000, 1710000002, 4, sourcesHash, sig);
    }

    function test_rate_limiter_allows_after_delay() public {
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

    function test_circuit_breaker_bypassed_after_staleness() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 4); // $1000

        // Jump 5 hours — beyond CIRCUIT_BREAKER_STALENESS (4h)
        vm.warp(1710000000 + 5 hours);
        uint256 ts = block.timestamp;

        // +50% would normally be rejected, but staleness bypass allows it
        _submitPrice(ETH_USD, 150000000000, ts, 4); // $1500

        (uint256 price, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price, 150000000000);
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

    function test_future_timestamp_over_boundary_reverts() public {
        // 5 minutes + 1 second — should revert
        uint256 ts = block.timestamp + 5 minutes + 1;

        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 100, ts, 3, sourcesHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.FutureTimestamp.selector,
                ts,
                block.timestamp + 5 minutes
            )
        );
        oracle.updatePrice(ETH_USD, 100, ts, 3, sourcesHash, sig);
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

        assertLt(gasUsed, 300_000);
        emit log_named_uint("updatePrice gas (cold)", gasUsed);
    }

    function test_gas_registerEnclave() public {
        KaskadPriceOracle fresh = new KaskadPriceOracle(EXPECTED_PCR0, address(mockVerifier));

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
        oracle = new KaskadPriceOracle(PCR0, address(mockVerifier));
        oracle.registerEnclave(hex"00");

        ethAgg  = new KaskadAggregatorV3(address(oracle), ETH_USD,  "ETH / USD");
        btcAgg  = new KaskadAggregatorV3(address(oracle), BTC_USD,  "BTC / USD");
        kasAgg  = new KaskadAggregatorV3(address(oracle), KAS_USD,  "KAS / USD");
        usdcAgg = new KaskadAggregatorV3(address(oracle), USDC_USD, "USDC / USD");
        igraAgg = new KaskadAggregatorV3(address(oracle), IGRA_USD, "IGRA / USD");
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

    function test_e2e_circuit_breaker_then_staleness_bypass() public {
        _relayPrice(ETH_USD, 100000000000, T0, 5); // $1000

        // 30s later: flash crash to $700 (-30%) → REJECTED
        vm.warp(T0 + 30);
        bytes32 srcHash = keccak256(abi.encodePacked("sources_", ETH_USD, T0+30));
        bytes memory sig = _sign(ETH_USD, 70000000000, T0+30, 5, srcHash);
        vm.prank(relayer);
        vm.expectRevert();
        oracle.updatePrice(ETH_USD, 70000000000, T0+30, 5, srcHash, sig);

        // Price stuck at $1000. 5 hours pass — staleness bypass kicks in.
        vm.warp(T0 + 5 hours);
        uint256 ts = block.timestamp;
        _relayPrice(ETH_USD, 70000000000, ts, 5); // $700 — now accepted

        (uint256 price, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price, 70000000000);
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

    function test_e2e_enclave_rotation_invalidates_old_signer() public {
        // Submit a price with original signer
        _relayPrice(ETH_USD, 212926000000, T0, 5);

        // New enclave boots with a new key
        uint256 newPk = 0xBEEF1;
        address newAddr = vm.addr(newPk);
        MockAttestationVerifier newVerifier = new MockAttestationVerifier(PCR0, newAddr);

        // Re-deploy oracle and re-register
        KaskadPriceOracle fresh = new KaskadPriceOracle(PCR0, address(newVerifier));
        fresh.registerEnclave(hex"00");
        assertEq(fresh.oracleSigner(), newAddr);

        // Old signer's signature is rejected on fresh oracle
        bytes32 srcHash = keccak256("test");
        bytes memory oldSig = _sign(ETH_USD, 100, T0, 3, srcHash);
        vm.prank(relayer);
        vm.expectRevert(KaskadPriceOracle.InvalidSignature.selector);
        fresh.updatePrice(ETH_USD, 100, T0, 3, srcHash, oldSig);
    }
}
