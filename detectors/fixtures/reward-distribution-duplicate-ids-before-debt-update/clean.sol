// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardDistributionDuplicateIdsBeforeDebtUpdateClean {
    mapping(uint256 => uint256) public rewardDebt;

    function claimReward(
        uint256 totalReward,
        uint256[] calldata ipIds
    ) external returns (uint256 paid) {
        uint256 rewardPerIP = totalReward / ipIds.length;
        for (uint256 i = 0; i < ipIds.length; ++i) {
            uint256 reward = rewardPerIP - rewardDebt[ipIds[i]];
            rewardDebt[ipIds[i]] += reward;
            paid += reward;
        }
    }
}
