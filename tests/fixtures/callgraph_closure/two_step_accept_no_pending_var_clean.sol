// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (clean): no pendingOwner state variable exists. The contract only has
// a single-step ownership transfer, so there is nothing to flag.
// Expected: two_step_accept_wrong_guard returns [] for "acceptOwnership".
contract TwoStepAcceptNoPendingVarClean {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // No pendingOwner var -> condition 2 fails -> not flagged.
    function acceptOwnership() external onlyOwner {
        // Hypothetical: just re-affirm ownership with no pending var.
        owner = msg.sender;
    }
}
