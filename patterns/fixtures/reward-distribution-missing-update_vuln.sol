// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardMissingUpdateVuln {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    uint256 public rewardPerTokenStored;

    // Contract DOES have an updateReward function (matches precondition),
    // but the entry points below fail to invoke it / the modifier before mutating.
    function updateReward(address account) public {
        rewards[account] = rewardPerTokenStored;
    }

    // VULN: deposit mutates `balances` but neither calls updateReward nor uses the modifier.
    function deposit(uint256 amt) external {
        balances[msg.sender] += amt;
    }

    // VULN: withdraw mutates `balances` without accrual.
    function withdraw(uint256 amt) external {
        balances[msg.sender] -= amt;
    }
}
