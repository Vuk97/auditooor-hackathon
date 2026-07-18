// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract BorrowOnBehalfPermissionlessClean {
    mapping(address => uint256) public accountBorrows;
    mapping(address => mapping(address => uint256)) public borrowAllowance;
    IERC20 public underlying;

    // CLEAN: requires borrow-delegation. The `borrowAllowance` check makes
    // the body match the negative regex, so the detector does NOT fire.
    function borrowBehalf(address borrower, uint256 amount) external returns (uint256) {
        uint256 allowed = borrowAllowance[borrower][msg.sender];
        require(allowed >= amount, "no delegation");
        borrowAllowance[borrower][msg.sender] = allowed - amount;
        accountBorrows[borrower] += amount;
        underlying.transfer(msg.sender, amount);
        return 0;
    }
}
