// SPDX-License-Identifier: MIT
// Fixture: mul-after-div-precision-loss — CLEAN
pragma solidity ^0.8.20;

library Math {
    function mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256) {
        return (a * b) / denominator;
    }
}

contract MulAfterDivClean {
    uint256 public constant YEAR = 365 days;
    mapping(address => uint256) public principal;

    // CLEAN: Math.mulDiv performs full-width multiply before single floor-div.
    function accrueFee(address user, uint256 ratePerSecond, uint256 elapsed) external view returns (uint256) {
        uint256 p = principal[user];
        return Math.mulDiv(p, ratePerSecond * elapsed, YEAR);
    }

    function shareOf(uint256 assets, uint256 totalAssets, uint256 totalSupply) external pure returns (uint256) {
        return Math.mulDiv(assets, totalSupply, totalAssets);
    }
}
