// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RewardRateVuln {
    uint256 public rewardRate;
    uint256 public rewardsDuration = 7 days;
    uint256 public periodFinish;
    uint256 public rewardPerTokenStored;
    uint256 public totalStaked;

    // This function is called by external admin to start new reward period
    function notifyRewardAmount(uint256 amount) external {
        require(block.timestamp > periodFinish, "previous period active");
        
        uint256 duration = rewardsDuration;
        rewardRate = amount / duration;
        
        periodFinish = block.timestamp + duration;
        rewardPerTokenStored = 0;
    }

    // Accrual logic that consumes rewardRate — proves this is not a leaf helper
    function earned(address account) public view returns (uint256) {
        uint256 elapsed = block.timestamp < periodFinish ? block.timestamp - (periodFinish - rewardsDuration) : rewardsDuration;
        return totalStaked > 0 ? (rewardRate * elapsed) / totalStaked : 0;
    }

    function claim() external {
        uint256 e = earned(msg.sender);
        rewardPerTokenStored += e;
    }
}