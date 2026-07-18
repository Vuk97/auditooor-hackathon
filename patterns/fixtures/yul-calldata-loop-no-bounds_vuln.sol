// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract YulCalldataLoopNoBoundsVuln {
    uint256 public total;

    function sum(uint256 n, uint256 offset) external {
        uint256 s;
        assembly {
            // VULN: no calldatasize bounds check.
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let v := calldataload(add(offset, mul(0x20, i)))
                s := add(s, v)
            }
        }
        total = s;
    }
}
