// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract YulClean {
    uint256 public total;

    function addDelta(uint256 delta) external {
        // CLEAN: 0.8 checked arithmetic
        total = total + delta;
    }
}
