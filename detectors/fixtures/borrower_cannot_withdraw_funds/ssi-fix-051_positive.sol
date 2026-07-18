// SPDX-License-Identifier: MIT
// Fixture for borrower-cannot-withdraw-funds
pragma solidity ^0.8.20;

contract BorrowerCannotWithdrawFundsPositive {
    uint256 internal balance;

    constructor() {
        balance = 1 ether;
    }

    function withdraw(uint256 amount) external {
        balance -= amount;
    }
}
