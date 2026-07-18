// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract YulCalldataLoopVuln {
    function parseOrders(bytes calldata) external pure returns (uint256 sum) {
        assembly {
            let p := 0x04
            let n := calldataload(p)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                sum := add(sum, calldataload(add(p, mul(add(i, 1), 0x20))))
            }
        }
    }
}