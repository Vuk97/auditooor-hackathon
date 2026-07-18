// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GaugeVuln {
    uint256 public currentEpoch;
    mapping(address => uint256) public pendingRewards; // single-slot, not per-epoch

    // BUG: advance epoch BEFORE settling the old-epoch pendingRewards into claimable.
    function notifyReward(address user, uint256 amount) external {
        currentEpoch = currentEpoch + 1;
        pendingRewards[user] = amount; // clobbers prior epoch's entitlement
    }

    function claim() external {
        uint256 amount = pendingRewards[msg.sender];
        pendingRewards[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
