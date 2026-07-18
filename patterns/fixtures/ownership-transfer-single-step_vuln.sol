// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: the contract holds a critical owner slot and exposes a single-step
// rotation setter. No sibling staging / acceptance handshake exists
// anywhere in the contract, so a miskeyed transfer permanently locks
// admin control.
contract OwnershipTransferSingleStepVuln {
    address public owner;
    address public admin;
    address public guardian;
    address public governance;

    constructor() {
        owner = msg.sender;
        admin = msg.sender;
        guardian = msg.sender;
        governance = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    modifier onlyGovernance() {
        require(msg.sender == governance, "not gov");
        _;
    }

    // VULN: one-shot ownership transfer. No staging slot, no accept hook.
    function transferOwnership(address newAddr) external onlyOwner {
        owner = newAddr;
    }

    // VULN: single-step admin rotation.
    function setAdmin(address newAddr) external onlyAdmin {
        admin = newAddr;
    }

    // VULN: single-step guardian rotation.
    function setGuardian(address newAddr) external onlyOwner {
        guardian = newAddr;
    }

    // VULN: single-step governance rotation.
    function setGovernance(address newAddr) external onlyGovernance {
        governance = newAddr;
    }
}
