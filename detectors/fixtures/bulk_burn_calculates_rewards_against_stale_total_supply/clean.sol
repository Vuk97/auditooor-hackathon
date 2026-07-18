// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BulkRewardBurnPoolClean {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public rewards;
    uint256 public totalSupply;
    uint256 public pendingRewardPool;

    constructor() {
        balanceOf[msg.sender] = 100 ether;
        totalSupply = 100 ether;
        pendingRewardPool = 10 ether;
    }

    function bulkBurnForRewards(address[] calldata accounts) external {
        for (uint256 i = 0; i < accounts.length; ++i) {
            address account = accounts[i];
            uint256 burnAmount = balanceOf[account];
            if (burnAmount == 0) {
                continue;
            }

            _burn(account, burnAmount);
            uint256 remainingSupply = totalSupply == 0 ? 1 : totalSupply;
            uint256 claimableReward = (pendingRewardPool * burnAmount) / remainingSupply;
            rewards[account] += claimableReward;
        }
    }

    function _burn(address account, uint256 amount) internal {
        balanceOf[account] -= amount;
        totalSupply -= amount;
    }
}
