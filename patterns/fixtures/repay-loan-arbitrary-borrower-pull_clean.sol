// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract RepayClean {
    struct Loan { address borrower; uint256 debt; }
    mapping(uint256 => Loan) public loans;
    IERC20 public loanToken;

    // CLEAN: pulls from msg.sender — whoever wants to pay off the loan
    // must supply their own funds.
    function repayLoan(uint256 loanId, uint256 amount) external {
        Loan storage l = loans[loanId];
        require(loanToken.transferFrom(msg.sender, address(this), amount), "ff");
        l.debt -= amount;
    }
}
