// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PriceCheckClean {
    uint256 public fromPrice;
    uint256 public toPrice;
    uint256 public priceChangeLimit = 1_05e16; // 1.05 * 1e18
    uint256 public constant PRECISION = 1e18;

    function checkRatio() external view returns (bool) {
        uint256 r = fromPrice * PRECISION / toPrice;
        return r <= priceChangeLimit;
    }
}
