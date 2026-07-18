// SPDX-License-Identifier: MIT
// Fixture: dust-redeem-floor-rounds-to-zero — VULNERABLE
// Detector MUST fire on every function here.
pragma solidity ^0.8.20;

contract DustRedeemFloorRoundsToZeroVuln {
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public shares;

    constructor(uint256 _assets, uint256 _supply) {
        totalAssets = _assets;
        totalSupply = _supply;
    }

    // VULN: amount = shares * total / supply with no zero-output revert.
    // Dust shareAmount → amount = 0 → caller's shares burnt for nothing.
    function redeem(uint256 shareAmount) external returns (uint256 amount) {
        amount = (shareAmount * totalAssets) / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= amount;
    }

    // VULN: same shape, underscore on the numerator variable name.
    function _redeem(address user, uint256 _shares) external returns (uint256 amount) {
        amount = (_shares * totalAssets) / totalSupply;
        shares[user] -= _shares;
        totalSupply -= _shares;
        totalAssets -= amount;
    }

    // VULN: withdraw path, same dust risk.
    function withdraw(uint256 shareAmount) external returns (uint256 amount) {
        amount = (shareAmount * totalAssets) / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= amount;
    }

    // VULN: unstake with underscore-prefixed denominator.
    function unstake(uint256 shareAmount) external returns (uint256 amount) {
        uint256 _total = totalSupply;
        amount = (shareAmount * totalAssets) / _total;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= amount;
    }

    // VULN: cashOut exit, same formula, no zero guard.
    function cashOut(uint256 shareAmount) external returns (uint256 amount) {
        amount = (shareAmount * totalAssets) / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= amount;
    }
}
