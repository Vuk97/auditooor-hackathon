// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract CastClean {
    function signedDelta(uint256 a, uint256 b) external pure returns (int256) {
        require(a <= uint256(type(int256).max), "a overflow");
        require(b <= uint256(type(int256).max), "b overflow");
        return int256(a) - int256(b);
    }
}
