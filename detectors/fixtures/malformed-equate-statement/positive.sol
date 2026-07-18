// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MalformedEquateStatementPositive {
    uint256 public threshold;

    function setThreshold(uint256 newThreshold) external {
        threshold == newThreshold;
    }
}
