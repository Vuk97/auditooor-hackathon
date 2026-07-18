// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (a): guard-in-helper.
// `entry()` has NO inline guard and NO modifier header, but it reaches the
// real `require(msg.sender == owner)` two hops away through a private helper.
// A header-only auth check would FALSE-POSITIVE flag `entry()` as missing-AC;
// has_guard_in_closure(entry) must return True.
//
// Mutation hook: tests remove the `require` line in `_auth()` to confirm the
// predicate flips True -> False (non-vacuity proof).
contract GuardInHelper {
    address public owner;
    uint256 public x;

    constructor() {
        owner = msg.sender;
    }

    function _auth() internal view {
        require(msg.sender == owner, "not owner"); // MUTATION-TARGET
    }

    function _helper() internal {
        _auth();
        x += 1;
    }

    // No inline guard, no modifier — guard is two hops away.
    function entry() external {
        _helper();
    }
}
