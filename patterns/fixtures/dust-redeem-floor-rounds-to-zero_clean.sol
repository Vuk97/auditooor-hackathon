// SPDX-License-Identifier: MIT
// Fixture: dust-redeem-floor-rounds-to-zero — CLEAN
// Detector MUST NOT fire on any function here.
pragma solidity ^0.8.20;

contract DustRedeemFloorRoundsToZeroClean {
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public shares;

    error ZeroAmount();
    error NoValue();

    constructor(uint256 _assets, uint256 _supply) {
        totalAssets = _assets;
        totalSupply = _supply;
    }

    // CLEAN: explicit `require(amount > 0, ...)` revert after computing
    // the floor result — dust redeems revert loudly.
    function redeem(uint256 shareAmount) external returns (uint256 amount) {
        amount = (shareAmount * totalAssets) / totalSupply;
        require(amount > 0, "ZeroAmount");
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= amount;
    }

    // CLEAN: custom-error revert via `revert ZeroAmount()`.
    function _redeem(address user, uint256 _shares) external returns (uint256 amount) {
        amount = (_shares * totalAssets) / totalSupply;
        if (amount == 0) revert ZeroAmount();
        shares[user] -= _shares;
        totalSupply -= _shares;
        totalAssets -= amount;
    }

    // CLEAN: `require(assets > 0)` form — matches the `assets?\s*>\s*0`
    // branch of the negative guard regex.
    function withdraw(uint256 shareAmount) external returns (uint256 assets) {
        assets = (shareAmount * totalAssets) / totalSupply;
        require(assets > 0, "ZeroAssets");
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assets;
    }

    // CLEAN: `revert NoValue()` branch.
    function unstake(uint256 shareAmount) external returns (uint256 amount) {
        uint256 _total = totalSupply;
        amount = (shareAmount * totalAssets) / _total;
        if (amount == 0) revert NoValue();
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= amount;
    }

    // CLEAN: `if (amount == 0) return;` early-exit form — no state
    // mutation on a zero result, so caller's shares are preserved.
    function cashOut(uint256 shareAmount) external returns (uint256 amount) {
        amount = (shareAmount * totalAssets) / totalSupply;
        if (amount == 0) return 0;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= amount;
    }
}
