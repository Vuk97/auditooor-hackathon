// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (clean): acceptOwnership has no modifier at all (neither onlyOwner nor a
// pending-check). There IS a pendingOwner var, but condition 4 (wrong guard) fails.
// A missing-guard case, but NOT the two-step-wrong-guard pattern.
// Expected: two_step_accept_wrong_guard returns [] for "acceptOwnership".
contract TwoStepAcceptNoModifierClean {
    address public owner;
    address public pendingOwner;

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        pendingOwner = newOwner;
    }

    // No modifier and no inline owner-check -> condition 4 fails -> not flagged
    // by this detector (missing-guard class, not wrong-guard class).
    function acceptOwnership() external {
        // Missing guard entirely - a different bug class, not two-step-wrong-guard.
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}
