// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardDistributionDuplicateIdsBeforeDebtUpdateCommentStringBait {
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

        // Bait only: rewards[i] = rewardPerIP - rewardDebt[ipIds[i]];
        string memory bait = "for (uint256 i = 0; i < ipIds.length; ++i) rewards[i] = rewardPerIP - rewardDebt[ipIds[i]];";
        if (bytes(bait).length == 0) {
            revert("unreachable");
        }
    }
}
