// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (a): ALWAYS-TRUE access tautology.
// require(msg.sender != admin || msg.sender != owner) is logically equivalent
// to `true` because no address can simultaneously BE both admin and owner;
// the OR of two disequalities on the same caller is always satisfied, so the
// guard is nullified. logic_tautology_suspects MUST flag kind=always-true-or.
contract TautologyAlwaysTrueOrSuspect {
    address public admin;
    address public owner;

    constructor(address _admin, address _owner) {
        admin = _admin;
        owner = _owner;
    }

    // Access check that is always true - attacker bypasses it trivially.
    function withdraw(uint256 amt) external returns (bool) {
        require(msg.sender != admin || msg.sender != owner, "bad");
        // (intended: require(msg.sender != admin && msg.sender != owner))
        payable(msg.sender).transfer(amt);
        return true;
    }
}
