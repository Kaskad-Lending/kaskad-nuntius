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
        _submitPrice(ETH_USD, 213000000000, 1710000010, 5); // +10s
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

        bytes32 sourcesHash = keccak256("test");
        bytes memory sig = _signUpdate(ETH_USD, 100, 1000, 3, sourcesHash);

        vm.expectRevert(KaskadPriceOracle.NoEnclaveRegistered.selector);
        unregistered.updatePrice(ETH_USD, 100, 1000, 3, sourcesHash, sig);
    }

    function test_updatePrice_reverts_invalid_signature() public {
        uint256 wrongKey = 0xBAD;
        bytes32 sourcesHash = keccak256("test");
        bytes32 messageHash = keccak256(
            abi.encodePacked(ETH_USD, uint256(100), uint256(1000), uint8(3), sourcesHash)
        );
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, ethSignedHash);

        vm.expectRevert(KaskadPriceOracle.InvalidSignature.selector);
        oracle.updatePrice(ETH_USD, 100, 1000, 3, sourcesHash, abi.encodePacked(r, s, v));
    }

    function test_updatePrice_reverts_stale_timestamp() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);

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
        vm.expectRevert(KaskadPriceOracle.InvalidSignature.selector);
        oracle.updatePrice(ETH_USD, 100, 1000, 3, bytes32(0), hex"aabbcc");
    }

    // ─── Circuit Breaker ─────────────────────────────────────────────

    function test_circuit_breaker_rejects_extreme_price_change() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 4); // $1000

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
