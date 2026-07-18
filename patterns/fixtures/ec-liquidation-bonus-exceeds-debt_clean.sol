// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: seize capped at repaidDebt * (1 + bonus%) — debt-relative, not collateral-relative
contract LiquidationBonusClean {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant BONUS_BPS = 1000; // 10% bonus on repaid debt

    function liquidate(address borrower, uint256 repayAmount) external {
        require(isUndercollateralized(borrower), "healthy");
        // CLEAN: bonus based on repaid debt amount — capped correctly
        uint256 bonus = repayAmount * BONUS_BPS / 10000;
        uint256 seize = repayAmount + bonus;
        // Also cap at available collateral (handles edge insolvency)
        if (seize > collateral[borrower]) {
            seize = collateral[borrower]; // full liquidation, bad debt socialized
        }
        debt[borrower] -= repayAmount;
        collateral[borrower] -= seize;
        collateral[msg.sender] += seize;
    }

    function isUndercollateralized(address user) public view returns (bool) {
        return collateral[user] * 80 / 100 < debt[user];
    }
}
