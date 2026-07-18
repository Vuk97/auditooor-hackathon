// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardVuln {
    uint256 public totalStaked;
    uint256 public rewardsPerBlock;

    // VULN: (stake / total) * rewards truncates early
    function pendingReward(uint256 stake) external view returns (uint256) {
        return (stake / totalStaked) * rewardsPerBlock;
    }
}
