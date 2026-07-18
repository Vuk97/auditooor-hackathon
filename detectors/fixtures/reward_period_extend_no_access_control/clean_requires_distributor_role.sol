pragma solidity ^0.8.20;

contract RewardPeriodExtendNoAccessControlCleanRequiresDistributorRole {
    uint256 public periodFinish;
    uint256 public rewardsDuration = 7 days;
    uint256 public rewardRate;
    uint256 public lastUpdateTime;
    address public distributor;

    modifier requiresDistributorRole() {
        require(_canExtendRewardPeriod(msg.sender), "not distributor");
        _;
    }

    constructor(address _distributor) {
        distributor = _distributor;
    }

    function _canExtendRewardPeriod(address caller) internal view returns (bool) {
        return caller == distributor;
    }

    function extendRewardPeriod(uint256 amount) external requiresDistributorRole {
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
