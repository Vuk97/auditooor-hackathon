// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CertoraStakingRewardIndexNonDecreasingPositive {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public userRewardPerTokenPaid;
    uint256 public rewardPerTokenStored;
    uint256 public totalSupply;

    function stake(uint256 amount) external {
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
        userRewardPerTokenPaid[msg.sender] = rewardPerTokenStored;
    }

    function accrue(uint256 rewardDelta) external {
        if (totalSupply == 0) {
            return;
        }
        rewardPerTokenStored += rewardDelta / totalSupply;
    }

    function resetRewardIndex(uint256 newIndex) external {
        rewardPerTokenStored = newIndex;
    }

    function earned(address account) external view returns (uint256) {
        unchecked {
            return balanceOf[account] * (rewardPerTokenStored - userRewardPerTokenPaid[account]);
        }
    }
}
