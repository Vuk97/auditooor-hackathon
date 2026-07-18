// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// (b) sstore to a LITERAL/constant slot inside assembly: a storage-slot
// collision risk (a hardcoded slot can alias a declared state var). asm_sstores
// must flag it with literal=True; asm_suspect kind=sstore-literal.
contract AsmSstoreLiteralSuspect {
    uint256 value;

    function setRaw(uint256 v) external {
        assembly {
            sstore(0x0, v)
        }
    }
}
