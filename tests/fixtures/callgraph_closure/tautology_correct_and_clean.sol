// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture: CORRECT access guard using AND.
// require(msg.sender != admin && msg.sender != owner) is the correct form -
// only callers who are NEITHER admin NOR owner pass. logic_tautology_suspects
// MUST NOT flag this (never-false-positive on the correct AND form).
contract TautologyCorrectAndClean {
    address public admin;
    address public owner;

    constructor(address _admin, address _owner) {
        admin = _admin;
        owner = _owner;
    }

    // Correct: AND of two disequalities - NOT always-true.
    function withdraw(uint256 amt) external returns (bool) {
        require(msg.sender != admin && msg.sender != owner, "forbidden");
        payable(msg.sender).transfer(amt);
        return true;
    }
}
