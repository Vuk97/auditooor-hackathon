// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RedundantSelfAssignmentIndicatesPotentialTypoOrLogicErrorClean {
    uint256 public redundantCounter;

    function redundantUpdateCounter() external {
        uint256 snapshot = redundantCounter;
        _updateCounter(snapshot + 1);
    }

    function _updateCounter(uint256 nextCounter) internal {
        redundantCounter = nextCounter;
    }
}
