// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract IsolatePoolClean {
    struct Loan { address borrower; uint256 amount; uint256 lastAction; }
    mapping(uint256 => Loan) public loans;
    mapping(address => mapping(address => bool)) public approvedRepayer;

    function isolateRepay(uint256 loanId, address onBehalfOf, uint256 amount) external {
        Loan storage l = loans[loanId];
        require(l.borrower == onBehalfOf, "borrower mismatch");
        require(msg.sender == loans[loanId].borrower || approvedRepayer[onBehalfOf][msg.sender], "not authorized");
        l.amount -= amount;
        l.lastAction = block.timestamp;
    }
}
