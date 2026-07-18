// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VoteWeighting {
    struct Point {
        uint256 bias;
        uint256 slope;
    }

    mapping(uint256 => Point) public pointsSum;
    mapping(uint256 => Point) public pointsWeight;

    function removeNominee(uint256 nextTime, uint256 biasDelta, uint256 removedBias) external {
        pointsSum[nextTime].bias -= biasDelta;
        pointsWeight[nextTime].bias = removedBias;
    }
}
