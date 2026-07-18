// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StakingRewardNoCheckpointVuln {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public userRewardPerTokenPaid;
    uint256 public rewardPerTokenStored;

    // VULN: _transfer moves balances but never checkpoints the reward
    // index for `from` or `to`. A fresh recipient keeps its default
    // `userRewardPerTokenPaid = 0`, so `earned(to)` equals
    // `balances[to] * rewardPerTokenStored` — a free claim. Detector
    // fires because the body lacks any `updateReward`/`_accrue`
    // checkpoint call.
    function _transfer(address from, address to, uint256 amount) internal {
        balances[from] -= amount;
        balances[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function earned(address account) public view returns (uint256) {
        return balances[account] * (rewardPerTokenStored - userRewardPerTokenPaid[account]);
    }
}
