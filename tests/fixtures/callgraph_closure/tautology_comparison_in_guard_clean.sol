// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture: comparison INSIDE a require/assert/if - NOT a dead comparison.
// When == or != is inside require(), the result IS consumed by the guard
// mechanism and must NOT be flagged. logic_tautology_suspects MUST NOT
// flag this (never-false-positive on guarded comparisons).
contract TautologyComparisonInGuardClean {
    address public admin;
    uint256 public balance;

    constructor(address _admin) {
        admin = _admin;
    }

    // Correct: == inside require() - the comparison result is consumed.
    function setBalanceRequire(uint256 amt) external {
        require(msg.sender == admin, "not admin");
        balance = amt;
    }

    // Correct: != inside require() - consumed.
    function setBalanceNe(uint256 amt) external {
        require(msg.sender != admin, "only non-admin");
        balance = amt;
    }

    // Correct: == inside if - consumed.
    function setBalanceIf(uint256 amt) external {
        if (msg.sender == admin) {
            balance = amt;
        }
    }

    // Correct: result assigned to a variable - not dead.
    function isAdmin() external view returns (bool ok) {
        ok = (msg.sender == admin);
    }
}
