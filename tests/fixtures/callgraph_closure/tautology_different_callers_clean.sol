// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture: OR with DIFFERENT callers (msg.sender vs a param) - NOT a tautology.
// require(msg.sender != admin || other != owner) is a real guard:
// it can fail when msg.sender IS admin AND other IS owner simultaneously.
// logic_tautology_suspects MUST NOT flag this (never-false-positive on
// different-identity OR).
contract TautologyDifferentCallersClean {
    address public admin;
    address public owner;

    constructor(address _admin, address _owner) {
        admin = _admin;
        owner = _owner;
    }

    // Not a tautology: the two sides compare DIFFERENT identities.
    function check(address other) external view returns (bool) {
        require(msg.sender != admin || other != owner, "blocked");
        return true;
    }
}
