pragma solidity ^0.8.20;

contract RewardPeriodExtendNoAccessControlCleanAmount {
    uint256 public periodFinish;
    uint256 public rewardsDuration = 7 days;
    uint256 public rewardRate;
    uint256 public lastUpdateTime;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function depositReward(uint256 amount) external {
        require(msg.sender == owner, "not owner");
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
