// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRewardToken {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract RewardClaimingDoSClean {
    address[] internal rewardTokens;
    mapping(address => uint256) internal rewardBalanceForUser;

    constructor(address[] memory initialRewardTokens) {
        rewardTokens = initialRewardTokens;
    }

    function setRewardBalanceForUser(address user, uint256 amount) external {
        rewardBalanceForUser[user] = amount;
    }

    function getRewardForUser(address user) external returns (bool) {
        uint256 rewardCount = rewardTokens.length;
        uint256 amount = rewardBalanceForUser[user];
        _syncRewardState(user);
        for (uint256 i = 0; i < rewardCount; ++i) {
            try IRewardToken(rewardTokens[i]).transfer(user, amount) returns (bool ok) {
                if (!ok) {
                    continue;
                }
            } catch {
                continue;
            }
        }
        return true;
    }

    function _syncRewardState(address user) internal view {
        require(user != address(0), "user");
    }
}
