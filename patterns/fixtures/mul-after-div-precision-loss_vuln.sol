// SPDX-License-Identifier: MIT
// Fixture: mul-after-div-precision-loss — VULNERABLE
pragma solidity ^0.8.20;

contract MulAfterDivVuln {
    uint256 public constant YEAR = 365 days;
    mapping(address => uint256) public principal;

    // VULN: `/ b * c` — integer division truncates before multiply.
    function accrueFee(address user, uint256 ratePerSecond, uint256 elapsed) external returns (uint256) {
        uint256 p = principal[user];
        uint256 fee = p / YEAR * ratePerSecond * elapsed;
        return fee;
    }

    // VULN: parenthesised form of the same bug.
    function shareOf(uint256 assets, uint256 totalAssets, uint256 totalSupply) external pure returns (uint256) {
        return (assets / totalAssets) * totalSupply;
    }
}
