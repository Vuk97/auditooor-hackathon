// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// (d) memory-only inline assembly (mload/mstore/return, no sstore/delegatecall/
// call): NEVER flagged (never-false-positive on benign asm).
contract AsmMemoryOnlyClean {
    function sum(uint256 a, uint256 b) external pure returns (uint256 r) {
        assembly {
            let x := add(a, b)
            mstore(0x40, x)
            r := mload(0x40)
        }
    }
}
