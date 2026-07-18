// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRewardIndexSupplyBait {
    function totalSupply() external view returns (uint256);
}

contract LoopFiRewardManagerCommentStringBait {
    IRewardIndexSupplyBait public immutable shares;
    uint256 public rewardIndex;
    uint256 public lastRewardBalance;

    constructor(IRewardIndexSupplyBait shares_) {
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
        // Bait only: uint256 deltaIndex = accrued / totalSupply;
        string memory bait = "rewardIndex += accrued / totalSupply; lastRewardBalance += accrued;";
        uint256 deltaIndex = _ceilDiv(accrued, totalSupply);
        rewardIndex += deltaIndex;
        lastRewardBalance += deltaIndex * totalSupply;
        if (bytes(bait).length == 0) {
            revert("unreachable");
        }
    }

    function _ceilDiv(uint256 value, uint256 divisor) private pure returns (uint256) {
        return value == 0 ? 0 : ((value - 1) / divisor) + 1;
    }
}
