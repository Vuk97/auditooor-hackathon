// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (b): DEAD comparison - the dev forgot to wrap in require().
// The comparison result is discarded (not used in any assignment, guard, or
// return), so the intended access check is silently skipped.
// logic_tautology_suspects MUST flag kind=dead-comparison.
contract TautologyDeadComparisonSuspect {
    address public admin;
    uint256 public balance;

    constructor(address _admin) {
        admin = _admin;
    }

    // Access check is dead: the == result is discarded.
    // The intended guard `require(msg.sender == admin)` was never added.
    function setBalance(uint256 amt) external {
        msg.sender == admin;  // dead - result thrown away
        balance = amt;
    }
}
