// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (suspect): acceptOwnership is gated by onlyOwner (the CURRENT owner)
// instead of checking msg.sender == pendingOwner. The pending owner can never
// accept (or the current owner can self-hijack the two-step).
// Expected: two_step_accept_wrong_guard flags function "acceptOwnership".
contract TwoStepAcceptWrongGuardSuspect {
    address public owner;
    address public pendingOwner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
    }

    // BUG: gated by onlyOwner (checks current owner), NOT pendingOwner.
    // The pendingOwner can never call this; the current owner can self-assign.
    function acceptOwnership() external onlyOwner {
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}
