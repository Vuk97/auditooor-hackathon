// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OracleClean {
    uint256 public cachedPrice;

    function getPrice() external view returns (uint256) {
        return cachedPrice;
    }

    function cachePrice(uint256 p) external {
        cachedPrice = p;
    }
}
