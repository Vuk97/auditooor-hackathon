// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract YulCalldataLoopClean {
    function parseOrders(bytes calldata) external pure returns (uint256 sum) {
        assembly {
            let p := 0x04
            let n := calldataload(p)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let ptr := add(p, mul(add(i, 1), 0x20))
                if iszero(lt(ptr, calldatasize())) {
                    revert(0, 0)
                }
                sum := add(sum, calldataload(ptr))
            }
        }
    }
}