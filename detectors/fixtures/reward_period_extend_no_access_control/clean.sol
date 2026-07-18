pragma solidity ^0.8.20;

contract RewardPeriodExtendNoAccessControlClean {
    uint256 public periodFinish;
    uint256 public rewardsDuration = 7 days;
    uint256 public rewardRate;
    uint256 public lastUpdateTime;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _owner) {
        owner = _owner;
    }

    function notifyRewardAmount(uint256 reward) external onlyOwner {
        require(reward > 0, "zero reward");

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
