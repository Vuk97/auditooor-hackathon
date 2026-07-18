// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRewardIndexSupplyClean {
    function totalSupply() external view returns (uint256);
}

contract LoopFiRewardManagerClean {
    IRewardIndexSupplyClean public immutable shares;
    uint256 public rewardIndex;
    uint256 public lastRewardBalance;

    constructor(IRewardIndexSupplyClean shares_) {
        shares = shares_;
    }

    function poke(uint256 currentRewardBalance) external {
        _updateRewardIndex(currentRewardBalance);
    }

    function _updateRewardIndex(uint256 currentRewardBalance) internal {
        uint256 totalSupply = shares.totalSupply();
        if (totalSupply == 0) {
            lastRewardBalance = currentRewardBalance;
            return;
        }

        uint256 accrued = currentRewardBalance - lastRewardBalance;
        uint256 deltaIndex = accrued / totalSupply;
        if (deltaIndex == 0) return;
        rewardIndex += deltaIndex;
        lastRewardBalance += deltaIndex * totalSupply;
    }
}
