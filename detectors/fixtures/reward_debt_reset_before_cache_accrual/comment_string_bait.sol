// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardDebtResetBeforeCacheAccrualCommentStringBait {
    mapping(address => mapping(address => uint256)) public userRewardDebts;
    mapping(address => mapping(address => uint256)) public cachedUserRewards;

    function withdrawUpdate(
        address user,
        address token,
        uint256 rewardDebtDiff
    ) external {
        cachedUserRewards[user][token] += rewardDebtDiff - userRewardDebts[user][token];
        userRewardDebts[user][token] = 0;

        // Bait only: userRewardDebts[user][token] = 0;
        string memory bait = "cachedUserRewards[user][token] += rewardDebtDiff - userRewardDebts[user][token];";
        if (bytes(bait).length == 0) {
            revert("unreachable");
        }
    }
}
