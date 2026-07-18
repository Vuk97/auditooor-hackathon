// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract RepayVuln {
    struct Loan { address borrower; uint256 debt; }
    mapping(uint256 => Loan) public loans;
    IERC20 public loanToken;

    // VULN: pulls from borrower (not msg.sender) without consent check.
    function repayLoan(uint256 loanId, uint256 amount) external {
        Loan storage l = loans[loanId];
        require(loanToken.transferFrom(l.borrower, address(this), amount), "ff");
        l.debt -= amount;
    }
}
