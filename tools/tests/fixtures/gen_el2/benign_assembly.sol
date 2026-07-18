// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A manual assembly selector switch whose default branch REVERTS on an unknown
// selector (a duplicate/unknown-selector rejection) - no privileged fallthrough.
// GEN-EL2 must stay SILENT (safe form c).
contract BenignAssembly {
    function dispatch() external {
        assembly {
            let sig := shr(224, calldataload(0))
            switch sig
            case 0x11111111 {
                sstore(0, 1)
            }
            case 0x22222222 {
                sstore(1, 2)
            }
            default {
                revert(0, 0)
            }
        }
    }
}
