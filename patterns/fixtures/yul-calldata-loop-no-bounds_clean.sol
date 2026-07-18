// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract YulCalldataLoopNoBoundsClean {
    uint256 public total;

    function sum(uint256 n, uint256 offset) external {
        uint256 s;
        assembly {
            // CLEAN: bounds check before each load.
            let end := add(offset, mul(0x20, n))
            if gt(end, calldatasize()) { revert(0, 0) }
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let v := calldataload(add(offset, mul(0x20, i)))
                s := add(s, v)
            }
        }
        total = s;
    }
}
