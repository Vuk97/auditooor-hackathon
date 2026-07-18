// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: checkpoint advances before the early return.

interface IYieldToken {
    function balanceOf(address) external view returns (uint256);
}

contract CleanDistributor {
    IYieldToken public immutable yieldToken;
    uint256 public lastUnderlyingBalance;
    uint256 public maxEndTime;
    uint256 public rewardRate;

    constructor(address t) {
        yieldToken = IYieldToken(t);
    }

    // CLEAN: sync checkpoint first, then short-circuit on zero.
    function distributeReward() external {
        uint256 currentBal = yieldToken.balanceOf(address(this));
        lastUnderlyingBalance = currentBal;              // bookkeeping first
        uint256 periodRewards = _computePeriod(currentBal);
        if (periodRewards == 0) return;
        // ... transfer rewards ...
    }

    function _updateRewardIndex() external {
        uint256 cur = yieldToken.balanceOf(address(this));
        lastUnderlyingBalance = cur;
        uint256 pending = _pending();
        if (pending == 0) return;
    }

    function _computePeriod(uint256) internal view returns (uint256) {
        if (block.timestamp > maxEndTime) return 0;
        return rewardRate;
    }

    function _pending() internal view returns (uint256) {
        return block.timestamp > maxEndTime ? 0 : rewardRate;
    }
}
