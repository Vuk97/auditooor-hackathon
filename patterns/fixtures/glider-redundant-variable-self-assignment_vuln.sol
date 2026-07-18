// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SelfAssignVuln {
    uint256 public feeBps;

    function setFee(uint256 newFeeBps) external {
        feeBps = feeBps;
    }

    function helper() internal {
        feeBps = 1;
    }
}