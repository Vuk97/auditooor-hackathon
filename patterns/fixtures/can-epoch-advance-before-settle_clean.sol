// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GaugeClean {
    uint256 public currentEpoch;
    mapping(uint256 => mapping(address => uint256)) public rewardsByEpoch;

    // Clean: settle into per-epoch slot BEFORE advancing the counter.
    function notifyReward(address user, uint256 amount) external {
        uint256 prevEpoch = currentEpoch;
        rewardsByEpoch[prevEpoch][user] += amount;
        _settlePrev(prevEpoch);
        currentEpoch = prevEpoch + 1;
    }

    function _settlePrev(uint256 epoch) internal { /* flush logic */ }

    function claim(uint256 epochId) external {
        uint256 amount = rewardsByEpoch[epochId][msg.sender];
        rewardsByEpoch[epochId][msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
