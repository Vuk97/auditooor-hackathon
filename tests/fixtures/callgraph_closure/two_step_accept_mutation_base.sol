// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Fixture (mutation base): same as suspect. The mutation test will add a
// require(msg.sender == pendingOwner) check to flip FLAGGED -> CLEAN, proving
// condition 5 (pending-check present) is load-bearing.
// Expected (base): two_step_accept_wrong_guard flags "acceptOwnership".
// Expected (mutated): two_step_accept_wrong_guard returns [] (clean).
contract TwoStepAcceptMutationBase {
    address public owner;
    address public pendingOwner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
    }

    function acceptOwnership() external onlyOwner {
        owner = pendingOwner;
        pendingOwner = address(0);
    }
}
