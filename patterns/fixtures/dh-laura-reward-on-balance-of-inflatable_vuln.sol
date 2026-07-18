// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function balanceOf(address) external view returns (uint256); }

contract LauraRewardVuln {
    IERC20 public stake;
    mapping(address => uint256) public userAmt;
    uint256 public accRewardPerShare;
    function pendingReward(address u) external view returns (uint256) {
        uint256 pool = stake.balanceOf(address(this));
        return pool == 0 ? 0 : userAmt[u] * accRewardPerShare * pool / 1e18;
    }
    function claim() external { /* ... */ }
}
