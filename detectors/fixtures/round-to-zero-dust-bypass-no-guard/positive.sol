// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Round-to-zero dust bypass: `amount * factor / DENOM` floors to 0 for small
// inputs and the floored value is consumed with NO zero-result guard.
// Each function is a distinct surface (fee / interest / proceeds) the four
// narrow sibling detectors each only cover one of.
contract RoundToZeroDustBypassVuln {
    uint256 public constant FEE_BPS = 30; // 0.30%
    uint256 public constant SCALE = 1e18;
    uint256 public collectedFees;
    uint256 public totalAssets;
    uint256 public totalSupply;
    mapping(address => uint256) public debt;
    mapping(address => uint256) public shares;

    // VULN: fee = amount * FEE_BPS / 10000 floors to 0 for amount <= 333.
    function transferWithFee(uint256 amount) external returns (uint256 out) {
        uint256 fee = amount * FEE_BPS / 10000;
        collectedFees += fee;
        out = amount - fee;
    }

    // VULN: interest = principal * rate / SCALE floors to 0 for dust loans.
    function accrue(uint256 rate) external {
        uint256 interest = debt[msg.sender] * rate / SCALE;
        debt[msg.sender] += interest;
    }

    // VULN: assets = shares * totalAssets / totalSupply burns dust shares for 0.
    function redeem(uint256 shareAmount) external returns (uint256 assets) {
        assets = shareAmount * totalAssets / totalSupply;
        shares[msg.sender] -= shareAmount;
        totalSupply -= shareAmount;
        totalAssets -= assets;
    }
}
