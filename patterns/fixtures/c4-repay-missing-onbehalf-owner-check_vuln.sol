// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IsolatePoolVuln {
    struct Loan { address borrower; uint256 amount; uint256 lastAction; }
    mapping(uint256 => Loan) public loans;

    /// VULN: anyone can repay on behalf of `onBehalfOf` with no authorization check.
    function isolateRepay(uint256 loanId, address onBehalfOf, uint256 amount) external {
        Loan storage l = loans[loanId];
        require(l.borrower == onBehalfOf, "borrower mismatch");
        l.amount -= amount;
        l.lastAction = block.timestamp;
    }
}
