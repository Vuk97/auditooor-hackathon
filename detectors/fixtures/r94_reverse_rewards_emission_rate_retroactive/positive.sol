pragma solidity ^0.8.20;

contract R94ReverseRewardsEmissionRateRetroactivePositive {
    uint256 public rewardRate;
    uint256 public rewardIndex;
    uint256 public lastUpdateTime;

    function setRewardRate(uint256 newRate) external {
        rewardRate = newRate;
        lastUpdateTime = block.timestamp;
    }

    function checkpoint() external {
        rewardIndex += rewardRate * (block.timestamp - lastUpdateTime);
        lastUpdateTime = block.timestamp;
    }
}
