// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardlossInStakingContractsClean {
    uint256 internal rewardpert;

    function _updateReward() internal {}

    function rewardPerToken() internal returns (bool) {
        _updateReward();
        return rewardpert > 0;
    }
}
