// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (clean): acceptOwnership correctly checks msg.sender == pendingOwner.
// Even though onlyOwner-family modifiers exist on other functions, the accept
// function itself uses the correct pending check -> NOT flagged.
// Expected: two_step_accept_wrong_guard returns [] for "acceptOwnership".
contract TwoStepAcceptCorrectPendingCheckClean {
    address public owner;
    address public pendingOwner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
    }

    // CORRECT: checks msg.sender == pendingOwner, not onlyOwner.
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}
