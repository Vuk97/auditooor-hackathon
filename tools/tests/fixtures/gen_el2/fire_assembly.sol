// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// A manual assembly selector switch whose `default` branch routes to a
// privileged delegatecall with NO duplicate/unknown-selector rejection.
// GEN-EL2 must FIRE (assembly-switch, no-duplicate-case-check).
contract FireAssembly {
    address internal privileged;

    function dispatch() external {
        address target = privileged;
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
                // unknown selector silently routed into the privileged target
                let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
                if iszero(ok) { revert(0, 0) }
            }
        }
    }
}
