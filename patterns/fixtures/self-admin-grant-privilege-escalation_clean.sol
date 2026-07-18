// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: addAdmin is onlyAdmin-gated AND revokes the caller's admin role
// in the same transaction (single-step handover). The single-admin
// invariant is preserved.
contract GovernanceClean {
    address public adminRole;
    mapping(address => bool) public admins;

    modifier onlyAdmin() {
        require(admins[msg.sender], "not admin");
        _;
    }

    constructor() {
        adminRole = msg.sender;
        admins[msg.sender] = true;
    }

    // Hand-over: grant the new admin, then revoke the caller's role so
    // only one admin exists at any time.
    function addAdmin(address a) external onlyAdmin {
        admins[a] = true;
        // Revoke-first guard — required for the single-admin invariant.
        removeAdmin(msg.sender);
    }

    function removeAdmin(address a) internal {
        admins[a] = false;
    }
}
