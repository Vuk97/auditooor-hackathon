pragma solidity ^0.8.20;

contract RewardPeriodExtendNoAccessControlCleanHelperAuth {
    uint256 public periodFinish;
    uint256 public rewardsDuration = 7 days;
    uint256 public rewardRate;
    uint256 public lastUpdateTime;
    address public rewardManager;

    constructor(address _rewardManager) {
        rewardManager = _rewardManager;
    }

    function _canExtendRewardPeriod(address caller) internal view returns (bool) {
        return caller == rewardManager;
    }

    function extendRewardPeriod(uint256 amount) external {
        require(_canExtendRewardPeriod(msg.sender), "not reward manager");
        require(amount > 0, "zero reward");

        if (block.timestamp >= periodFinish) {
            rewardRate = amount / rewardsDuration;
        } else {
            uint256 remaining = periodFinish - block.timestamp;
            uint256 leftover = remaining * rewardRate;
            rewardRate = (amount + leftover) / rewardsDuration;
        }

        lastUpdateTime = block.timestamp;
        periodFinish = block.timestamp + rewardsDuration;
    }
}
