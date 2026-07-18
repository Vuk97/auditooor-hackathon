// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StakeBalanceRewardAccountingClean {
    mapping(address => uint256) internal stakeBalanceLedger;
    uint256 internal stakeBalanceCurrent;
    uint256 internal rewardCheckpoint;

    function deposit(uint256 amount) external {
        stakeBalanceLedger[msg.sender] += amount;
        stakeBalanceCurrent += amount;
    }

    function _accrueRewards(address account) internal {
        rewardCheckpoint = stakeBalanceLedger[account];
    }

    // CLEAN: updates stake accounting through an accrue helper before using it.
    function stakeBalanceCheckpoint(address account) internal returns (bool) {
        _accrueRewards(account);
        rewardCheckpoint += stakeBalanceCurrent;
        return stakeBalanceLedger[account] < stakeBalanceCurrent;
    }

    function preview(address account) external returns (bool) {
        return stakeBalanceCheckpoint(account);
    }
}
