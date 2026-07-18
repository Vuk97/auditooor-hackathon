// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: self-liquidation blocked by liquidator != borrower check
contract SelfLiquidationClean {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant BONUS_BPS = 1000;

    function depositCollateral(uint256 amount) external {
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        require(collateral[msg.sender] * 80 / 100 >= debt[msg.sender] + amount, "LTV");
        debt[msg.sender] += amount;
    }

    // CLEAN: self-liquidation explicitly blocked
    function liquidate(address borrower, uint256 repayAmount) external {
        require(msg.sender != borrower, "no self-liquidation"); // key fix
        require(isUndercollateralized(borrower), "not undercollateralized");
        uint256 bonus = repayAmount * BONUS_BPS / 10000;
        uint256 seize = repayAmount + bonus;
        require(seize <= collateral[borrower], "seize exceeds collateral");
        debt[borrower] -= repayAmount;
        collateral[borrower] -= seize;
        collateral[msg.sender] += seize;
    }

    function isUndercollateralized(address user) public view returns (bool) {
        return collateral[user] * 80 / 100 < debt[user];
    }
}
