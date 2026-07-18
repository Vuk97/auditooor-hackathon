// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract YulVuln {
    uint256 public total;

    function addDelta(uint256 delta) external {
        uint256 cur = total;
        uint256 next;
        assembly {
            next := add(cur, delta)  // VULN: no overflow guard
        }
        total = next;
    }
}
