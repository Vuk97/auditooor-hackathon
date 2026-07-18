// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract QuorumThresholdBoundsClean {
    uint256 internal constant MIN_QUORUM_BPS = 5_100;

    address[] public members;
    uint256 public quorumThreshold;

    function setQuorumThreshold(uint256 newThreshold) external {
        _validateQuorumThreshold(newThreshold);
        quorumThreshold = newThreshold;
    }

    function _validateQuorumThreshold(uint256 newThreshold) internal view {
        require(
            newThreshold * 10_000 >= members.length * MIN_QUORUM_BPS,
            "threshold too low"
        );
    }
}
