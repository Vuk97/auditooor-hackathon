pragma solidity ^0.8.20;

contract RewardPeriodExtendNoAccessControlPositive {
    uint256 public periodFinish;
    uint256 public rewardsDuration = 7 days;
    uint256 public rewardRate;
    uint256 public lastUpdateTime;
    bytes32 public constant REWARD_ADMIN_ROLE = keccak256("REWARD_ADMIN_ROLE");

    function hasRole(bytes32, address) internal pure returns (bool) {
        return false;
    }

    function extendRewardPeriod(uint256 reward) external {
        if (hasRole(REWARD_ADMIN_ROLE, msg.sender)) {
            rewardRate = rewardRate;
        }

        if (block.timestamp >= periodFinish) {
            rewardRate = reward / rewardsDuration;
        } else {
            uint256 remaining = periodFinish - block.timestamp;
            uint256 leftover = remaining * rewardRate;
            rewardRate = (reward + leftover) / rewardsDuration;
        }

        lastUpdateTime = block.timestamp;
        periodFinish = block.timestamp + rewardsDuration;
    }
}
