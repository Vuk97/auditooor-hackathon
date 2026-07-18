// SPDX-License-Identifier: MIT
// Fixture: return-value-inverted-meaning — VULNERABLE
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

contract ReturnValueInvertedVuln {
    mapping(address => bool) public denied;
    mapping(address => bool) public admins;

    // VULN (shape A): the function is named `isAuthorized` (predicate), but
    // the explicit `return false;` sits on the success fall-through after the
    // error-guard branch reverts. Callers that use
    // `require(isAuthorized(user), ...)` always revert on legitimate users.
    function isAuthorized(address user) external view returns (bool) {
        if (denied[user]) {
            revert("denied");
        }
        // This is the success path, but the boolean returned is `false`.
        return false;
    }

    // VULN (shape B): the function is named `canWithdraw` (predicate). The
    // `return true;` is emitted inside the guard/error branch, and the real
    // success fall-through reverts. Any caller that does
    // `if (canWithdraw(u)) { ... }` will treat the error as allowance.
    function canWithdraw(address user) external view returns (bool) {
        if (denied[user]) {
            return true;
        }
        revert("not eligible");
    }
}
