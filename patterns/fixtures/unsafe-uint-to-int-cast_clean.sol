// SPDX-License-Identifier: MIT
// Fixture: unsafe-uint-to-int-cast — CLEAN
// Detector MUST NOT fire on any function here.
pragma solidity ^0.8.20;

// Minimal SafeCast — mimics OpenZeppelin's surface.
library SafeCast {
    function toInt256(uint256 value) internal pure returns (int256) {
        require(value <= uint256(type(int256).max), "SafeCast: value too large");
        return int256(value);
    }

    function toInt128(uint128 value) internal pure returns (int128) {
        require(value <= uint128(type(int128).max), "SafeCast: value too large");
        return int128(value);
    }

    function toInt64(uint64 value) internal pure returns (int64) {
        require(value <= uint64(type(int64).max), "SafeCast: value too large");
        return int64(value);
    }
}

contract UnsafeUintToIntCastClean {
    using SafeCast for uint256;
    using SafeCast for uint128;

    uint256 public cumulativeFunding;
    mapping(address => uint256) public fundingAtEntry;
    mapping(address => int256) public pnl;

    // CLEAN fix #1: route every uint -> int conversion through SafeCast.
    // The library's toInt256 reverts if the value exceeds int256.max.
    function settle(address trader) external {
        int256 delta = cumulativeFunding.toInt256() - fundingAtEntry[trader].toInt256();
        pnl[trader] += delta;
    }

    // CLEAN fix #2: explicit bounds check before casting.
    function signedDiff(uint256 a, uint256 b) external pure returns (int256) {
        require(a <= type(uint256).max / 2, "a overflow");
        require(b <= type(uint256).max / 2, "b overflow");
        return int256(a) - int256(b);
    }

    // CLEAN fix #3: home-rolled _safeCast helper.
    function tickDelta(uint128 u) external pure returns (int128) {
        return _safeCast(u);
    }

    function _safeCast(uint128 u) internal pure returns (int128) {
        require(u <= uint128(type(int128).max), "cast overflow");
        return int128(u);
    }

    // CLEAN fix #4: SafeCast.toInt128 library call.
    function marginUpdate(uint128 gross, uint128 fee) external pure returns (int128) {
        return gross.toInt128() - fee.toInt128();
    }
}
