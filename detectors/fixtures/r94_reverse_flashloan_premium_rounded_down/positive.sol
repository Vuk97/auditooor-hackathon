// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract R94ReverseFlashloanPremiumRoundedDownPositive {
    uint256 public premiumBps = 9;
    uint256 public premiumCollected;

    event FlashLoanTaken(address indexed borrower, uint256 amount, uint256 premium);

    function flashLoan(address borrower, uint256 amount) external returns (uint256 premium) {
        premium = amount * premiumBps / 10000;
        premiumCollected += premium;
        emit FlashLoanTaken(borrower, amount, premium);
    }
}
