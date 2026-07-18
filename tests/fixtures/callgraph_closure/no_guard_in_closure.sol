// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (b): header-only / no-real-guard-in-closure.
// `entry()` reaches a helper that does arithmetic but NO caller-identity check
// anywhere in the closure. has_guard_in_closure(entry) must return False
// (this is a genuine missing-AC candidate). The `require` here is a numeric
// bound, NOT a msg.sender / tx.origin guard, so the default caller-identity
// guard predicate must NOT count it.
contract NoGuardInClosure {
    uint256 public x;

    function _helper(uint256 amt) internal {
        require(amt < 1000, "too big"); // numeric bound, NOT an auth guard
        x += amt;
    }

    function entry(uint256 amt) external {
        _helper(amt);
    }
}
