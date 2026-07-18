// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BulkRewardBurnPool {
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
        uint256 supplySnapshot = totalSupply;

        for (uint256 i = 0; i < accounts.length; ++i) {
            address account = accounts[i];
            uint256 burnAmount = balanceOf[account];
            if (burnAmount == 0) {
                continue;
            }

            uint256 claimableReward = (pendingRewardPool * burnAmount) / supplySnapshot;
            rewards[account] += claimableReward;
            _burn(account, burnAmount);
        }
    }

    function _burn(address account, uint256 amount) internal {
        balanceOf[account] -= amount;
        totalSupply -= amount;
    }
}
