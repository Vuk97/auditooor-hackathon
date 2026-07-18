// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RedundantSelfAssignmentIndicatesPotentialTypoOrLogicErrorVulnerable {
    uint256 public redundantCounter;

    function redundantUpdateCounter() external {
        uint256 snapshot = redundantCounter;
        redundantCounter = redundantCounter;
        require(snapshot == redundantCounter, "sanity");
    }
}
