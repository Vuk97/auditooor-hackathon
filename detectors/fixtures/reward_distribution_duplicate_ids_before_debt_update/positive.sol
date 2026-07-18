// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardDistributionDuplicateIdsBeforeDebtUpdatePositive {
    mapping(uint256 => uint256) public rewardDebt;

    function getAvailableReward(
        uint256 totalReward,
        uint256[] calldata ipIds
    ) external view returns (uint256[] memory rewards) {
        rewards = new uint256[](ipIds.length);
        uint256 rewardPerIP = totalReward / ipIds.length;
        for (uint256 i = 0; i < ipIds.length; ++i) {
            rewards[i] = rewardPerIP - rewardDebt[ipIds[i]];
        }
    }
}
