// SPDX-License-Identifier: MIT
// Fixture: role_grant_divergence_dsl — CLEAN
// Detector MUST NOT fire on this contract — no role-gated asset-flow function.
pragma solidity ^0.8.20;

contract RoleGrantDivergenceClean {
    // No onlyRoles on asset-flow functions → no structural match
    function doThing(uint256 x) external pure returns (uint256) {
        return x + 1;
    }

    function compute(uint256 a, uint256 b) external pure returns (uint256) {
        return a * b;
    }
}
