// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: liquidation seizes collateral * bonus% — not capped at repaidDebt + bonus
// Loss ref: Compound V2 shortfall math / Aave bad debt scenarios, 2022-2023
// https://rekt.news/compound-rekt-ii/
contract LiquidationBonusVuln {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant BONUS_BPS = 1100; // 110% — means seize 110% of total collateral

    function liquidate(address borrower, uint256 repayAmount) external {
        require(isUndercollateralized(borrower), "healthy");
        // VULN: bonus computed on TOTAL COLLATERAL, not on repaid debt
        uint256 seize = collateral[borrower] * BONUS_BPS / 10000;
        // seize can exceed collateral[borrower] OR repaidDebt + bonus
        debt[borrower] -= repayAmount;
        // underflow if seize > collateral — or over-seizes relative to debt
        collateral[borrower] -= seize;
        collateral[msg.sender] += seize;
    }

    function isUndercollateralized(address user) public view returns (bool) {
        return collateral[user] * 80 / 100 < debt[user];
    }
}
