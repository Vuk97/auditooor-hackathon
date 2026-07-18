// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MaliciousStakerVoteDelayClean {
    struct Weight {
        uint256 balance;
        uint256 stakeTime;
    }

    mapping(address => Weight) internal stakeWeights;
    uint256 internal lastVoteWeight;

    function setUserVoteDelegate(address delegate, uint256 amount) external {
        Weight storage weight = stakeWeights[delegate];
        uint256 oldBalance = weight.balance;
        weight.balance += amount;
        if (oldBalance == 0) {
            weight.stakeTime = block.timestamp;
        } else {
            weight.stakeTime =
                ((weight.stakeTime * oldBalance) + (block.timestamp * amount)) /
                weight.balance;
        }
    }

    function clearUserVoteDelegate(address delegate, uint256 amount) external {
        Weight storage weight = stakeWeights[delegate];
        require(weight.balance >= amount, "insufficient delegated stake");
        weight.balance -= amount;
        if (weight.balance == 0) {
            weight.stakeTime = 0;
        }
    }

    function voteWeight(address delegate) external returns (uint256) {
        _accrue(delegate);
        Weight storage weight = stakeWeights[delegate];
        lastVoteWeight = weight.balance * (block.timestamp - weight.stakeTime);
        return lastVoteWeight;
    }

    function _accrue(address delegate) internal {
        Weight storage weight = stakeWeights[delegate];
        if (weight.balance == 0) {
            weight.stakeTime = block.timestamp;
        }
    }
}
