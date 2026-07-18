// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amt) external returns (bool);
    function transferFrom(address from, address to, uint256 amt) external returns (bool);
}

contract StakingRewardOverlapClean {
    IERC20 public stakeToken;            // satisfies precondition
    IERC20 public rewardToken;           // separate reward asset
    mapping(address => uint256) public staking;
    mapping(address => uint256) public rewards;

    constructor(IERC20 _stake, IERC20 _reward) {
        stakeToken = _stake;
        rewardToken = _reward;
    }

    function deposit(uint256 amt) external {
        stakeToken.transferFrom(msg.sender, address(this), amt);
        staking[msg.sender] += amt;
    }

    function withdraw(uint256 amt) external {
        staking[msg.sender] -= amt;
        stakeToken.transfer(msg.sender, amt);
    }

    // CLEAN: reward is paid in a SEPARATE token, so stake principal is
    // untouched. The claim path does not reference stakeToken/stakedToken/
    // stakingToken/_token/token variable names on a transfer.
    function claimReward() external {
        uint256 owed = rewards[msg.sender];
        rewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, owed);
    }

    function harvest() external {
        uint256 owed = rewards[msg.sender];
        rewards[msg.sender] = 0;
        rewardToken.transfer(msg.sender, owed);
    }
}
