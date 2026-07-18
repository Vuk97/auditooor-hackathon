// SPDX-License-Identifier: MIT
// Fixture: role_grant_divergence_dsl — VULNERABLE (structural match)
// Detector MUST fire on this contract.
pragma solidity ^0.8.20;

abstract contract RolesAuth {
    modifier onlyRoles(bytes32) {
        _;
    }
}

contract RoleGrantDivergenceVuln is RolesAuth {
    function unwrap(address asset, uint256 amount) external onlyRoles("WRAPPER_ROLE") {
        // If WRAPPER_ROLE is not granted on mainnet, every call reverts.
        amount = amount;
        asset = asset;
    }
}
