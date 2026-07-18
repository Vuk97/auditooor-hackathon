// SPDX-License-Identifier: MIT
// Fixture: return-value-inverted-meaning — CLEAN
// Detector MUST NOT fire on this contract.
pragma solidity ^0.8.20;

contract ReturnValueInvertedClean {
    mapping(address => bool) public denied;
    mapping(address => bool) public admins;

    // CLEAN: predicate semantics aligned with the name. Returns `true` on the
    // success path and `false` on the negative path. No `revert` is mixed with
    // a contradictory `return true/false` on an adjacent branch.
    function isAuthorized(address user) external view returns (bool) {
        if (denied[user]) {
            return false;
        }
        return true;
    }

    // CLEAN: pure-boolean style. No revert + return mix.
    function canWithdraw(address user) external view returns (bool) {
        if (denied[user]) {
            return false;
        }
        return true;
    }
}
