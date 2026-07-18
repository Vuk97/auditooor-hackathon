// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReverseRewardsDistributionEndRawSubtractionPositive {
    uint256 public distributionEnd = 1_000_000;
    uint256 public lastUpdateTime = 100;
    uint256 public rewardRate = 1e18;

    function rewardPerToken() public view returns (uint256) {
        uint256 currentTime = block.timestamp;
        uint256 elapsed = distributionEnd - currentTime;
        return elapsed * rewardRate + _noop(currentTime);
    }

    function earned(address) external view returns (uint256) {
        uint256 currentTime = block.timestamp;
        return (currentTime - lastUpdateTime) * rewardRate + _noop(currentTime);
    }

    function _noop(uint256 value) internal pure returns (uint256) {
        return value - value;
    }
}
