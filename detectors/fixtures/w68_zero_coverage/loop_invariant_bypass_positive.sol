// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// VULNERABLE: loop uses <= against array length, off-by-one out-of-bounds
// read - the loop invariant is bypassed at the boundary.
contract LoopInvariantBypassVulnerable {
    uint256[] public items;

    function sumItems() external view returns (uint256 total) {
        for (uint256 i = 0; i <= items.length; i++) {
            total += items[i];
        }
    }
}
