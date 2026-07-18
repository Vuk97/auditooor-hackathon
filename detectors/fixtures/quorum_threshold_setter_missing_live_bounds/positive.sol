// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract QuorumThresholdBoundsPositive {
    address[] public members;
    uint256 public quorumThreshold;

    function setQuorumThreshold(uint256 newThreshold) external {
        quorumThreshold = newThreshold;
    }
}
