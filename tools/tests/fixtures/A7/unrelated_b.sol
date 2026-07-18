// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// An entirely independent module: no reference to LonePool, no shared base.
// Coincidentally uses the same field name. Must NOT be paired as a sibling.
contract IndependentBook {
    uint256 public totalReserves;

    function record(uint256 v) external {
        totalReserves = v;
    }
}
