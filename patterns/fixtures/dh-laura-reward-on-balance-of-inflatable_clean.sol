// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function balanceOf(address) external view returns (uint256); }

contract LauraRewardClean {
    IERC20 public stake;
    mapping(address => uint256) public userAmt;
    uint256 public totalStaked;
    uint256 public accRewardPerShare;
    function pendingReward(address u) external view returns (uint256) {
        return totalStaked == 0 ? 0 : userAmt[u] * accRewardPerShare / 1e18;
    }
    function deposit(uint256 a) external { userAmt[msg.sender] += a; totalStaked += a; }
    function claim() external { /* ... */ }
}
