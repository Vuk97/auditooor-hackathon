// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// (c) sstore to a DECLARED storage var's .slot inside assembly: NOT a collision
// risk (the slot is the var's own compiler-assigned canonical slot, referenced
// by `.slot`, not a hardcoded/arithmetic literal). asm_sstores must NOT flag it
// (literal=False, declared-var .slot -> not surfaced as asm_suspect).
contract AsmSstoreDeclaredClean {
    uint256 value;

    function setVal(uint256 v) external {
        assembly {
            sstore(value.slot, v)
        }
    }
}
