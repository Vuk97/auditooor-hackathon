// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract StakeBalanceRewardAccountingPositive {
    mapping(address => uint256) internal stakeBalanceLedger;
    uint256 internal stakeBalanceCurrent;
    uint256 internal rewardCheckpoint;

    function deposit(uint256 amount) external {
        stakeBalanceLedger[msg.sender] += amount;
        stakeBalanceCurrent += amount;
    }

    // VULN: reads stake-balance state and mutates reward accounting without any
    // accrue/update/sync/check/refresh helper.
    function stakeBalanceCheckpoint(address account) internal returns (bool) {
        rewardCheckpoint += stakeBalanceCurrent;
        return stakeBalanceLedger[account] < stakeBalanceCurrent;
    }

    function preview(address account) external returns (bool) {
        return stakeBalanceCheckpoint(account);
    }
}
