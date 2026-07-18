// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Math {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

contract ReverseRewardsDistributionEndRawSubtractionClean {
    using Math for uint256;

    uint256 public distributionEnd = 1_000_000;
    uint256 public lastUpdateTime = 100;
    uint256 public rewardRate = 1e18;

    function lastTimeRewardApplicable() public view returns (uint256) {
        return Math.min(block.timestamp, distributionEnd);
    }

    function rewardPerToken() public view returns (uint256) {
        uint256 currentTime = lastTimeRewardApplicable();
        uint256 elapsed = currentTime - lastUpdateTime;
        return elapsed * rewardRate + _noop(currentTime);
    }

    function earned(address) external view returns (uint256) {
        uint256 currentTime = lastTimeRewardApplicable();
        return (currentTime - lastUpdateTime) * rewardRate + _noop(currentTime);
    }

    function _noop(uint256 value) internal pure returns (uint256) {
        return value - value;
    }
}
