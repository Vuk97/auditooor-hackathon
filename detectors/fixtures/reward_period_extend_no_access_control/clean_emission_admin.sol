pragma solidity ^0.8.20;

contract RewardPeriodExtendNoAccessControlCleanEmissionAdmin {
    uint256 public periodFinish;
    uint256 public rewardsDuration = 7 days;
    uint256 public rewardRate;
    uint256 public lastUpdateTime;
    address public emissionAdmin;

    modifier onlyEmissionAdmin() {
        require(_canExtendRewardPeriod(msg.sender), "not emission admin");
        _;
    }

    constructor(address _emissionAdmin) {
        emissionAdmin = _emissionAdmin;
    }

    function _canExtendRewardPeriod(address caller) internal view returns (bool) {
        return caller == emissionAdmin;
    }

    function extendRewardPeriod(uint256 amount) external onlyEmissionAdmin {
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
