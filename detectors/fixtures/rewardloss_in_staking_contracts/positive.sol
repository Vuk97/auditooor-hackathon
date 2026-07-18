// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardlossInStakingContractsPositive {
    uint256 internal rewardpert;

    function rewardPerToken() internal returns (bool) {
        return rewardpert > 0;
    }
}
