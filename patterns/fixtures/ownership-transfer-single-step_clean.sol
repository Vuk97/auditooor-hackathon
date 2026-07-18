// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: two-step accept handshake for every critical role. The contract
// defines pendingOwner / pendingAdmin / pendingGuardian / pendingGovernance
// and matching acceptOwnership / acceptAdmin / acceptGuardian /
// acceptGovernance functions. The contract-level precondition
// `has_no_function_body_matching` fails against these marker names, so
// the pattern must skip this contract without inspecting individual
// setters.
contract OwnershipTransferSingleStepClean {
    address public owner;
    address public pendingOwner;

    address public admin;
    address public pendingAdmin;

    address public guardian;
    address public pendingGuardian;

    address public governance;
    address public pendingGovernance;

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

    // Staging half: writes to pendingOwner, not owner.
    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
    }

    // Acceptance half: incoming address proves control of the key before
    // owner slot is rotated.
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function setAdmin(address newAdmin) external onlyAdmin {
        pendingAdmin = newAdmin;
    }

    function acceptAdmin() external {
        require(msg.sender == pendingAdmin, "not pending admin");
        admin = pendingAdmin;
        pendingAdmin = address(0);
    }

    function setGuardian(address newGuardian) external onlyOwner {
        pendingGuardian = newGuardian;
    }

    function acceptGuardian() external {
        require(msg.sender == pendingGuardian, "not pending guardian");
        guardian = pendingGuardian;
        pendingGuardian = address(0);
    }

    function setGovernance(address newGov) external onlyGovernance {
        pendingGovernance = newGov;
    }

    function acceptGovernance() external {
        require(msg.sender == pendingGovernance, "not pending governance");
        governance = pendingGovernance;
        pendingGovernance = address(0);
    }
}
