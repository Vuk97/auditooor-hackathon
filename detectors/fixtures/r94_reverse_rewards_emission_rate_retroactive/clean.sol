pragma solidity ^0.8.20;

contract R94ReverseRewardsEmissionRateRetroactiveClean {
    uint256 public rewardRate;
    uint256 public rewardIndex;
    uint256 public lastUpdateTime;

    function setRewardRate(uint256 newRate) external {
        _updateRewardIndex();
        rewardRate = newRate;
        lastUpdateTime = block.timestamp;
    }

    function _updateRewardIndex() internal {
        rewardIndex += rewardRate * (block.timestamp - lastUpdateTime);
        lastUpdateTime = block.timestamp;
    }
}
