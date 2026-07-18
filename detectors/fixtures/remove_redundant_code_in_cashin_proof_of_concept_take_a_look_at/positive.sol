// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CashInMissingAccountingGuardPositive {
    uint256 internal balance;

    function cashIn(uint256 amount) external {
        balance = amount;
    }
}
