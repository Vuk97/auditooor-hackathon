// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULN: reward distributor returns early on zero-reward, skipping the
// checkpoint update. Once zero triggers (e.g., after maxEndTime), all
// subsequent accruals are stranded.
// Modeled on Morpheus M-04 (Code4rena 2025-08).

interface IYieldToken {
    function balanceOf(address) external view returns (uint256);
}

contract VulnDistributor {
    IYieldToken public immutable yieldToken;
    uint256 public lastUnderlyingBalance;
    uint256 public maxEndTime;
    uint256 public rewardRate;

    constructor(address t) {
        yieldToken = IYieldToken(t);
    }

    // VULN 1: early return before updating lastUnderlyingBalance.
    function distributeReward() external {
        uint256 currentBal = yieldToken.balanceOf(address(this));
        uint256 periodRewards = _computePeriod(currentBal);

        if (periodRewards == 0) return; // <--- skips state update

        lastUnderlyingBalance = currentBal;
        // ... transfer rewards ...
    }

    // VULN 2: _updateRewardIndex with same defect.
    function _updateRewardIndex() external {
        uint256 pending = _pending();
        if (pending == 0) {
            return; // lastAccrual not advanced
        }
        lastUnderlyingBalance = yieldToken.balanceOf(address(this));
    }

    function accrueReward() external {
        uint256 delta = _computeDelta();
        if (delta == 0) return;
        lastUnderlyingBalance = yieldToken.balanceOf(address(this));
    }

    function _computePeriod(uint256) internal view returns (uint256) {
        if (block.timestamp > maxEndTime) return 0;
        return rewardRate;
    }

    function _pending() internal view returns (uint256) {
        return block.timestamp > maxEndTime ? 0 : rewardRate;
    }

    function _computeDelta() internal view returns (uint256) {
        return block.timestamp > maxEndTime ? 0 : 1;
    }
}
