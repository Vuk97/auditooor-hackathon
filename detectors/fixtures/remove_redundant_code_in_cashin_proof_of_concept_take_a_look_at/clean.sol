// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CashInMissingAccountingGuardClean {
    uint256 internal balance;
    uint256 internal totalSupplyCap = 10000;

    function cashIn(uint256 amount) external {
        require(amount <= totalSupplyCap, "amount cap");
        balance = amount;
    }
}
