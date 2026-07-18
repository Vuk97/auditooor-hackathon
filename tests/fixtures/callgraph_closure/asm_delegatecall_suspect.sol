// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// (a) Yul-level delegatecall inside inline assembly: a proxy/upgrade backdoor
// primitive that the SOLIDITY-level `has_low_level_delegatecall` predicate
// CANNOT see (the delegatecall is in Yul, not a `.delegatecall()` member call).
// asm_delegatecalls(fn) must flag it; asm_suspect kind=delegatecall.
contract AsmDelegatecallSuspect {
    address implementation;

    function forward(bytes calldata data) external returns (bool ok) {
        address impl = implementation;
        assembly {
            calldatacopy(0, data.offset, data.length)
            ok := delegatecall(gas(), impl, 0, data.length, 0, 0)
        }
    }
}
