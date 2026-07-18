// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StakingRewardNoCheckpointClean {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;
    uint256 public rewardPerTokenStored;

    function _updateReward(address account) internal {
        if (account != address(0)) {
            rewards[account] += balances[account] * (rewardPerTokenStored - userRewardPerTokenPaid[account]);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
    }

    // CLEAN: transfer checkpoints BOTH sides of the move. Detector does
    // NOT fire because the negative regex matches `_updateReward(`.
    function _transfer(address from, address to, uint256 amount) internal {
        _updateReward(from);
        _updateReward(to);
        balances[from] -= amount;
        balances[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }
}
