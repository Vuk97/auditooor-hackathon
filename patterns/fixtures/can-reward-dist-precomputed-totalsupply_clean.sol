// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardDistClean {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    uint256 public rewardPerShare;

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    // Clean: accrue reward to existing holders BEFORE the mint.
    function deposit(uint256 amount) external {
        uint256 fee = (amount * 200) / 10_000;
        if (totalSupply > 0) {
            rewardPerShare += (fee * 1e18) / totalSupply; // live total, pre-mint
        }
        _mint(msg.sender, amount - fee);
    }
}
