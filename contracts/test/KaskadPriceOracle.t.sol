// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/KaskadPriceOracle.sol";
import "../src/KaskadAggregatorV3.sol";

contract KaskadPriceOracleTest is Test {
    KaskadPriceOracle oracle;
    KaskadAggregatorV3 ethAggregator;

    uint256 internal signerPrivateKey;
    address internal signer;
    address internal owner;

    bytes32 internal constant ETH_USD = keccak256("ETH/USD");
    bytes32 internal constant BTC_USD = keccak256("BTC/USD");

    function setUp() public {
        signerPrivateKey = 0xA11CE;
        signer = vm.addr(signerPrivateKey);
        owner = address(this);

        oracle = new KaskadPriceOracle(signer);
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

    // ─── Constructor ─────────────────────────────────────────────────

    function test_constructor() public view {
        assertEq(oracle.owner(), owner);
        assertEq(oracle.oracleSigner(), signer);
        assertEq(oracle.DECIMALS(), 8);
    }

    function test_constructor_reverts_zero_signer() public {
        vm.expectRevert(KaskadPriceOracle.ZeroAddress.selector);
        new KaskadPriceOracle(address(0));
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

        // Verify storage
        (uint256 storedPrice, uint256 storedTs, uint8 storedSources, uint80 roundId) =
            oracle.getLatestPrice(ETH_USD);
        assertEq(storedPrice, price);
        assertEq(storedTs, ts);
        assertEq(storedSources, sources);
        assertEq(roundId, 1);
    }

    function test_updatePrice_increments_roundId() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);
        _submitPrice(ETH_USD, 213000000000, 1710000001, 5);
        _submitPrice(ETH_USD, 213100000000, 1710000002, 3);

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
        _submitPrice(ETH_USD, 200000000000, 1710000001, 4);

        // Round 1 should still be accessible
        (uint256 price1, uint256 ts1, ) = oracle.getRoundData(ETH_USD, 1);
        assertEq(price1, 100000000000);
        assertEq(ts1, 1710000000);

        // Latest should be round 2
        (uint256 price2, , , ) = oracle.getLatestPrice(ETH_USD);
        assertEq(price2, 200000000000);
    }

    // ─── Rejections ──────────────────────────────────────────────────

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

    function test_updatePrice_reverts_same_timestamp() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);

        bytes32 sourcesHash = keccak256("test_sources");
        bytes memory sig = _signUpdate(ETH_USD, 212900000000, 1710000000, 4, sourcesHash);

        vm.expectRevert(
            abi.encodeWithSelector(
                KaskadPriceOracle.StalePrice.selector,
                uint256(1710000000),
                uint256(1710000000)
            )
        );
        oracle.updatePrice(ETH_USD, 212900000000, 1710000000, 4, sourcesHash, sig);
    }

    function test_updatePrice_reverts_short_signature() public {
        vm.expectRevert(KaskadPriceOracle.InvalidSignature.selector);
        oracle.updatePrice(ETH_USD, 100, 1000, 3, bytes32(0), hex"aabbcc");
    }

    // ─── Admin ───────────────────────────────────────────────────────

    function test_setOracleSigner() public {
        address newSigner = address(0xBEEF);
        oracle.setOracleSigner(newSigner);
        assertEq(oracle.oracleSigner(), newSigner);
    }

    function test_setOracleSigner_reverts_unauthorized() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(KaskadPriceOracle.Unauthorized.selector);
        oracle.setOracleSigner(address(0xBEEF));
    }

    function test_transferOwnership() public {
        address newOwner = address(0xCAFE);
        oracle.transferOwnership(newOwner);
        assertEq(oracle.owner(), newOwner);

        // Old owner can no longer call admin functions
        vm.expectRevert(KaskadPriceOracle.Unauthorized.selector);
        oracle.setOracleSigner(address(0xBEEF));
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

    function test_aggregator_getRoundData() public {
        _submitPrice(ETH_USD, 100000000000, 1710000000, 3);
        _submitPrice(ETH_USD, 200000000000, 1710000001, 4);

        (uint80 roundId, int256 answer, , , ) = ethAggregator.getRoundData(1);
        assertEq(roundId, 1);
        assertEq(answer, int256(uint256(100000000000)));
    }

    function test_aggregator_latestAnswer() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);
        assertEq(ethAggregator.latestAnswer(), int256(uint256(212926000000)));
    }

    function test_aggregator_latestTimestamp() public {
        _submitPrice(ETH_USD, 212926000000, 1710000000, 4);
        assertEq(ethAggregator.latestTimestamp(), 1710000000);
    }

    function test_aggregator_decimals() public view {
        assertEq(ethAggregator.decimals(), 8);
    }

    function test_aggregator_description() public view {
        assertEq(ethAggregator.description(), "ETH / USD");
    }

    // ─── Gas Benchmarks ──────────────────────────────────────────────

    function test_gas_updatePrice() public {
        bytes32 sourcesHash = keccak256("test");
        bytes memory sig = _signUpdate(ETH_USD, 212926000000, 1710000000, 4, sourcesHash);

        uint256 gasBefore = gasleft();
        oracle.updatePrice(ETH_USD, 212926000000, 1710000000, 4, sourcesHash, sig);
        uint256 gasUsed = gasBefore - gasleft();

        // First write is expensive (cold storage slots). ~262K gas.
        // Subsequent updates to same asset: ~82K gas (warm slots).
        assertLt(gasUsed, 300_000);
        emit log_named_uint("updatePrice gas", gasUsed);
    }
}
