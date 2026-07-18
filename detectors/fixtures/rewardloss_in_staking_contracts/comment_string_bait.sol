// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RewardlossInStakingContractsCommentStringBait {
    uint256 internal rewardpert;

    function _updateReward() internal {}

    function rewardPerToken() internal returns (bool) {
        _updateReward();
        string memory bait = "return rewardpert > 0 without updateReward";
        // Bait only: rewardpert and missing update text above must not create a hit.
        return bytes(bait).length > 0;
    }
}
