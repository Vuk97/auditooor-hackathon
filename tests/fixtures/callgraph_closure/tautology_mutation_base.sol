// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Mutation base: ALWAYS-TRUE OR tautology (FLAGGED).
// One-edit mutation: replace || with && to produce the correct form (CLEAN).
// The test_mutation_or_to_and_flips_annotation test applies this mutation
// and asserts the annotation flips FLAGGED->clean (non-vacuity proof).
contract TautologyMutationBase {
    address public admin;
    address public owner;

    constructor(address _admin, address _owner) {
        admin = _admin;
        owner = _owner;
    }

    // Base: || (FLAGGED as always-true-or tautology).
    function access() external view returns (bool) {
        require(msg.sender != admin || msg.sender != owner, "x");
        return true;
    }
}
