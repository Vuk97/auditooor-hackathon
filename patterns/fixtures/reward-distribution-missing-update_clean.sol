// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardMissingUpdateClean {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    uint256 public rewardPerTokenStored;

    modifier updateReward(address account) {
        rewards[account] = rewardPerTokenStored;
        _;
    }

    // Also expose a plain updateReward() to satisfy contract-level precondition
    // via the modifier/function name regex match.
    function _updateReward(address account) internal {
        rewards[account] = rewardPerTokenStored;
    }

    // CLEAN: modifier applies reward accrual before the balance mutation.
    function deposit(uint256 amt) external updateReward(msg.sender) {
        balances[msg.sender] += amt;
    }

    // CLEAN: same pattern on withdraw.
    function withdraw(uint256 amt) external updateReward(msg.sender) {
        balances[msg.sender] -= amt;
    }
}
