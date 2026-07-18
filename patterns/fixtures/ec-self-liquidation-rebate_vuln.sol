// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: no liquidator != borrower check — self-liquidation pockets bonus
// Loss ref: Mango Markets ~$116M, October 2022
// https://rekt.news/mango-markets-rekt/
contract SelfLiquidationVuln {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant BONUS_BPS = 1000; // 10%

    function depositCollateral(uint256 amount) external {
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        require(collateral[msg.sender] * 80 / 100 >= debt[msg.sender] + amount, "LTV");
        debt[msg.sender] += amount;
    }

    // VULN: msg.sender == borrower allowed — attacker self-liquidates for bonus
    function liquidate(address borrower, uint256 repayAmount) external {
        // MISSING: require(msg.sender != borrower, "no self-liquidation")
        require(isUndercollateralized(borrower), "not undercollateralized");
        uint256 bonus = repayAmount * BONUS_BPS / 10000;
        uint256 seize = repayAmount + bonus;
        debt[borrower] -= repayAmount;
        collateral[borrower] -= seize;
        collateral[msg.sender] += seize; // attacker gets own bonus
    }

    function isUndercollateralized(address user) public view returns (bool) {
        return collateral[user] * 80 / 100 < debt[user];
    }
}
