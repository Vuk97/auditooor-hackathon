// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: addAdmin is onlyAdmin-gated but creates a second admin without
// revoking the caller's role. The contract elsewhere assumes a single
// admin. A compromised or malicious current admin can promote any
// address (including themselves under a new identity) and keep their
// own admin rights intact, bypassing the single-admin invariant.
contract GovernanceVuln {
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

    // Promotes `a` to admin. No revocation of the caller. Multi-admin
    // state is silently created.
    function addAdmin(address a) external onlyAdmin {
        admins[a] = true;
    }
}
