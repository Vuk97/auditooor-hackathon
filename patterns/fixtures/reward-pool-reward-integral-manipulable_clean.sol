// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract RewardPoolRewardIntegralManipulableClean {
    IERC20 public rewardToken;
    // Triggers contract-level precondition.
    uint256 public integral;
    uint256 public rewardIndex;

    // Donation-resistance: snapshotted reward + supply. Only updated by
    // privileged deposit-reward and stake/unstake flows. Presence of
    // `trackedBalance` / `snapshottedSupply` suppresses the detector.
    uint256 public trackedBalance;
    uint256 public snapshottedSupply;

    mapping(address => uint256) public userBalance;

    constructor(address _rewardToken) {
        rewardToken = IERC20(_rewardToken);
    }

    // CLEAN: integral uses the delta between current and tracked reward
    // balance (rejecting raw donations) and snapshotted supply.
    function _calcRewardIntegral() external {
        uint256 current = rewardToken.balanceOf(address(this));
        if (current <= trackedBalance || snapshottedSupply == 0) return;
        uint256 delta = current - trackedBalance;
        integral += (delta * 1e18) / snapshottedSupply;
        trackedBalance = current;
    }

    // CLEAN: rewardPerToken reads snapshotted supply, not live totalSupply.
    function rewardPerToken() external view returns (uint256) {
        if (snapshottedSupply == 0) return rewardIndex;
        return rewardIndex + ((trackedBalance) * 1e18) / snapshottedSupply;
    }

    // CLEAN: earned() uses snapshotted supply + tracked reward balance.
    function earned(address account) external view returns (uint256) {
        if (snapshottedSupply == 0) return 0;
        return (userBalance[account] * trackedBalance) / snapshottedSupply;
    }

    // Controlled stake flow: updates snapshottedSupply, never trusts live totalSupply.
    function stake(uint256 amount) external {
        userBalance[msg.sender] += amount;
        snapshottedSupply += amount;
    }

    function unstake(uint256 amount) external {
        userBalance[msg.sender] -= amount;
        snapshottedSupply -= amount;
    }
}
