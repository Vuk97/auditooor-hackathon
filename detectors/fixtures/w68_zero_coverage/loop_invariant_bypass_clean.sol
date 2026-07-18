// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// CLEAN: loop uses strict < against array length.
contract LoopInvariantBypassSafe {
    uint256[] public items;

    function sumItems() external view returns (uint256 total) {
        for (uint256 i = 0; i < items.length; i++) {
            total += items[i];
        }
    }
}
