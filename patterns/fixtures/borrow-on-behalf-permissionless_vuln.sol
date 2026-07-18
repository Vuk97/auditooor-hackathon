// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BorrowOnBehalfPermissionlessVuln {
    mapping(address => uint256) public accountBorrows;
    IERC20 public underlying;

    // VULN: any caller can open debt on `borrower`'s account and receive
    // the borrowed cash. No delegation / allowance check. Detector fires
    // because: function is external, name matches borrowBehalf, param is
    // named `borrower`, writes accountBorrows, and body has no
    // `borrowAllowance` / `msg.sender == borrower` guard.
    function borrowBehalf(address borrower, uint256 amount) external returns (uint256) {
        accountBorrows[borrower] += amount;
        underlying.transfer(msg.sender, amount);
        return 0;
    }
}
