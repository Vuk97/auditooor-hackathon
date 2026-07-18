// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function balanceOf(address) external view returns (uint256); }

contract ConvexRewardIntegralVuln {
    IERC20 public rewardToken;
    uint256 public rewardIntegral;
    uint256 public totalSupply;
    function _calcRewardIntegral() internal {
        uint256 bal = rewardToken.balanceOf(address(this));
        if (totalSupply > 0) rewardIntegral += bal * 1e18 / totalSupply;
    }
    function poke() external { _calcRewardIntegral(); }
}
